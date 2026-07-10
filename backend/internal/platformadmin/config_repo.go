package platformadmin

// §6.18 #122 P-2 — the flag write path. A flag change and its immutable audit row are written in ONE tx (WithSystem —
// flags are platform-managed), so a change is never applied without its evidence, and vice-versa.

import (
	"context"
	"encoding/json"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository writes flag changes + reads audit history.
type Repository struct{ db *database.DB }

// NewRepository builds the writer.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// FlagChange is a validated flag mutation ready to apply + audit.
type FlagChange struct {
	Key         string
	Scope       string
	ScopeRef    string
	Enabled     bool
	SafetyClass string
	ActorID     uuid.UUID
	Reason      string
}

func boolJSON(b bool) []byte {
	m, _ := json.Marshal(map[string]bool{"enabled": b})
	return m
}

// ApplyFlagChange upserts the flag row and appends an immutable audit row in one tx. Returns the prior enabled value
// (nil if the flag did not exist) for the caller's security-delta message.
func (r *Repository) ApplyFlagChange(ctx context.Context, ch FlagChange) (old *bool, err error) {
	e := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var prev bool
		qerr := tx.QueryRow(ctx, `SELECT enabled FROM platform_feature_flags WHERE key=$1 AND scope=$2 AND scope_ref=$3`,
			ch.Key, ch.Scope, ch.ScopeRef).Scan(&prev)
		var oldJSON []byte
		switch {
		case qerr == pgx.ErrNoRows:
			// old stays nil
		case qerr != nil:
			return qerr
		default:
			old = &prev
			oldJSON = boolJSON(prev)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO platform_feature_flags (key, scope, scope_ref, enabled, updated_by, updated_at)
			VALUES ($1,$2,$3,$4,$5,now())
			ON CONFLICT (key, scope, scope_ref) DO UPDATE SET enabled=EXCLUDED.enabled, updated_by=EXCLUDED.updated_by, updated_at=now()`,
			ch.Key, ch.Scope, ch.ScopeRef, ch.Enabled, ch.ActorID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO platform_config_audit (entity, key, scope, scope_ref, old_value, new_value, safety_class, actor_id, reason)
			VALUES ('flag',$1,$2,$3,$4,$5,$6,$7,$8)`,
			ch.Key, ch.Scope, ch.ScopeRef, oldJSON, boolJSON(ch.Enabled), ch.SafetyClass, ch.ActorID, ch.Reason)
		return err
	})
	return old, e
}

// AuditRejected records a rejected mutation attempt (e.g. an immutable-key flip) so the attempt is on the record.
func (r *Repository) AuditRejected(ctx context.Context, ch FlagChange, reason string) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO platform_config_audit (entity, key, scope, scope_ref, new_value, safety_class, actor_id, reason)
			VALUES ('flag',$1,$2,$3,$4,$5,$6,$7)`,
			ch.Key, ch.Scope, ch.ScopeRef, boolJSON(ch.Enabled), ch.SafetyClass, ch.ActorID, "REJECTED: "+reason)
		return err
	})
}

// AuditRow is one config-audit record (for rollback + history).
type AuditRow struct {
	ID       uuid.UUID
	Key      string
	Scope    string
	ScopeRef string
	Enabled  bool
	Reason   string
}

// GetFlagAudit reads a single flag-audit row's new_value (the target of a rollback).
func (r *Repository) GetFlagAudit(ctx context.Context, id uuid.UUID) (AuditRow, bool, error) {
	var row AuditRow
	found := false
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var newVal []byte
		e := tx.QueryRow(ctx, `SELECT id, key, scope, scope_ref, new_value, reason FROM platform_config_audit WHERE id=$1 AND entity='flag'`, id).
			Scan(&row.ID, &row.Key, &row.Scope, &row.ScopeRef, &newVal, &row.Reason)
		if e == pgx.ErrNoRows {
			return nil
		}
		if e != nil {
			return e
		}
		var m map[string]bool
		_ = json.Unmarshal(newVal, &m)
		row.Enabled = m["enabled"]
		found = true
		return nil
	})
	return row, found, err
}
