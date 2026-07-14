package platformadmin

// §6.18 #122 P-2 — the flag write path. A flag change and its immutable audit row are written in ONE tx (WithSystem —
// flags are platform-managed), so a change is never applied without its evidence, and vice-versa.

import (
	"context"
	"encoding/json"
	"time"

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
	ExpiresAt   *time.Time // Reinf-B: set for a protected weakening; nil clears any prior time-box
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
		if _, err := tx.Exec(ctx, `INSERT INTO platform_feature_flags (key, scope, scope_ref, enabled, expires_at, updated_by, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,now())
			ON CONFLICT (key, scope, scope_ref) DO UPDATE SET enabled=EXCLUDED.enabled, expires_at=EXCLUDED.expires_at, updated_by=EXCLUDED.updated_by, updated_at=now()`,
			ch.Key, ch.Scope, ch.ScopeRef, ch.Enabled, ch.ExpiresAt, ch.ActorID); err != nil {
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

// CreateWindow inserts a maintenance window (padmin).
func (r *Repository) CreateWindow(ctx context.Context, scope, scopeRef string, startsAt, endsAt time.Time, suppressNotif, pauseSLA bool, banner string, actorID uuid.UUID) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO maintenance_windows (scope, scope_ref, starts_at, ends_at, suppress_notifications, pause_sla, banner, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, scope, scopeRef, startsAt, endsAt, suppressNotif, pauseSLA, banner, actorID)
		return e
	})
}

// ActiveMaintenance reports whether an active window covering the tenant (or global) suppresses notifications and/or
// pauses SLA. Read system-side by the notify/SLA path.
func (r *Repository) ActiveMaintenance(ctx context.Context, tenantID uuid.UUID) (suppressNotif, pauseSLA bool, err error) {
	e := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT COALESCE(bool_or(suppress_notifications),false), COALESCE(bool_or(pause_sla),false)
			  FROM maintenance_windows
			 WHERE now() BETWEEN starts_at AND ends_at
			   AND (scope='global' OR (scope='tenant' AND scope_ref=$1::text))`, tenantID).Scan(&suppressNotif, &pauseSLA)
	})
	return suppressNotif, pauseSLA, e
}

// FlagRow is a single feature-flag row for the platform-admin flags read model. SafetyClass and SecureDefault are
// derived (not stored) so the UI can show why a flag is guarded and whether its current value is the secure one.
type FlagRow struct {
	Key           string     `json:"key"`
	Scope         string     `json:"scope"`
	ScopeRef      string     `json:"scope_ref"`
	Enabled       bool       `json:"enabled"`
	SafetyClass   string     `json:"safety_class"`
	SecureDefault bool       `json:"secure_default"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// ListFlags returns every configured feature flag (platform-admin read). Cross-scope → WithSystem.
func (r *Repository) ListFlags(ctx context.Context) ([]FlagRow, error) {
	var out []FlagRow
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT key, scope, scope_ref, enabled, expires_at, updated_at
			FROM platform_feature_flags ORDER BY key, scope, scope_ref`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var f FlagRow
			if se := rows.Scan(&f.Key, &f.Scope, &f.ScopeRef, &f.Enabled, &f.ExpiresAt, &f.UpdatedAt); se != nil {
				return se
			}
			f.SafetyClass = string(ClassOf(f.Key))
			f.SecureDefault = SecureDefault(f.Key)
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// ExpiredWeakenings returns flags whose time-box has elapsed (Reinf-B), read cross-scope (system sees all).
func (r *Repository) ExpiredWeakenings(ctx context.Context, limit int) ([]FlagChange, error) {
	var out []FlagChange
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT key, scope, scope_ref FROM platform_feature_flags
			WHERE expires_at IS NOT NULL AND expires_at < now() ORDER BY expires_at ASC LIMIT $1`, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var c FlagChange
			if se := rows.Scan(&c.Key, &c.Scope, &c.ScopeRef); se != nil {
				return se
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// RevertFlag sets a flag back to a value, clears its time-box, and appends an audit row (Reinf-B auto-revert).
func (r *Repository) RevertFlag(ctx context.Context, key, scope, scopeRef string, secure bool, reason string) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE platform_feature_flags SET enabled=$4, expires_at=NULL, updated_at=now()
			WHERE key=$1 AND scope=$2 AND scope_ref=$3`, key, scope, scopeRef, secure); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO platform_config_audit (entity, key, scope, scope_ref, new_value, safety_class, reason)
			VALUES ('flag',$1,$2,$3,$4,'protected',$5)`, key, scope, scopeRef, boolJSON(secure), reason)
		return e
	})
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
