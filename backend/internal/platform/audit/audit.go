// Package audit writes immutable, append-only audit events (NFR-003).
// Every admin/analyst/AI/SOAR/integration action must be recorded, ideally in the
// same transaction as the action so the two commit atomically.
package audit

import (
	"context"
	"encoding/json"

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
