// Package audit writes immutable, append-only audit events (NFR-003).
// Every admin/analyst/AI/SOAR/integration action must be recorded, ideally in the
// same transaction as the action so the two commit atomically.
package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Entry is a single audit record.
type Entry struct {
	ActorID    uuid.UUID      // who (zero for system)
	ActorEmail string         // denormalised for readability
	Action     string         // e.g. "tenant.create", "auth.login", "case.close"
	Target     string         // e.g. "case:<uuid>"
	Metadata   map[string]any // non-sensitive context (NEVER secrets)
	RequestID  string
}

// Record inserts an audit event within the given transaction. tenant_id is taken
// from the transaction's app.current_tenant GUC via the table default, so this is
// naturally tenant-scoped under RLS.
func Record(ctx context.Context, tx pgx.Tx, e Entry) error {
	meta, err := json.Marshal(e.Metadata)
	if err != nil {
		meta = []byte("{}")
	}
	var actor any
	if e.ActorID != uuid.Nil {
		actor = e.ActorID
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO audit_log (actor_id, actor_email, action, target, metadata, request_id)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		actor, e.ActorEmail, e.Action, e.Target, meta, e.RequestID,
	)
	return err
}

// LogEntry is a stored, read-back audit record (with its timestamp).
type LogEntry struct {
	ActorEmail string    `json:"actor_email"`
	Action     string    `json:"action"`
	Target     string    `json:"target"`
	RequestID  string    `json:"request_id"`
	At         time.Time `json:"at"`
}

// FindByActionContains returns the tenant's audit rows whose action or target
// contains needle, oldest first — used to assemble an incident's audit trail for an
// evidence pack (the mutation middleware records the URL path, which carries the
// incident id, in `action`). Tenant-scoped via RLS; reads are permitted on the
// append-only log.
func FindByActionContains(ctx context.Context, db *database.DB, tenantID uuid.UUID, needle string, limit int) ([]LogEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	var out []LogEntry
	err := db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT actor_email, action, target, request_id, at
			   FROM audit_log
			  WHERE action ILIKE '%'||$1||'%' OR target ILIKE '%'||$1||'%'
			  ORDER BY at ASC LIMIT $2`, needle, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e LogEntry
			if err := rows.Scan(&e.ActorEmail, &e.Action, &e.Target, &e.RequestID, &e.At); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}
