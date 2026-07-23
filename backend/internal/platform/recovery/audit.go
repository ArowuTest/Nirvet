package recovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditSeam identifies immutable records known to exist before the backup. Their
// presence after restore proves the evidentiary timeline crosses the recovery
// boundary instead of silently restarting from an empty log.
type AuditSeam struct {
	RequestIDs []string
	BackupID   string
	RestoreID  string
}

// ValidateAuditContinuity checks pre-backup markers and the database-level
// append-only controls on the restored instance. It is read-only.
func ValidateAuditContinuity(ctx context.Context, owner *pgxpool.Pool, seam AuditSeam) (string, error) {
	if owner == nil {
		return "", fmt.Errorf("recovery: restored audit database is required")
	}
	if len(seam.RequestIDs) == 0 || strings.TrimSpace(seam.BackupID) == "" || strings.TrimSpace(seam.RestoreID) == "" {
		return "", fmt.Errorf("recovery: audit seam markers, backup id, and restore id are required")
	}
	seen := make(map[string]struct{}, len(seam.RequestIDs))
	for _, requestID := range seam.RequestIDs {
		requestID = strings.TrimSpace(requestID)
		if requestID == "" {
			return "", fmt.Errorf("recovery: audit seam contains an empty request id")
		}
		if _, duplicate := seen[requestID]; duplicate {
			return "", fmt.Errorf("recovery: duplicate audit seam request id %q", requestID)
		}
		seen[requestID] = struct{}{}
		var count int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE request_id=$1`, requestID).Scan(&count); err != nil {
			return "", fmt.Errorf("recovery: inspect audit seam %q: %w", requestID, err)
		}
		if count != 1 {
			return "", fmt.Errorf("recovery: audit seam %q count=%d want 1", requestID, count)
		}
	}

	// The application role deliberately retains UPDATE/DELETE table privileges so
	// PostgreSQL can reach the immutable-row trigger and reject the mutation with an
	// auditable error. Recovery therefore validates the restored trigger itself,
	// rather than incorrectly treating those grants as evidence of mutability.
	var immutableTriggers int
	if err := owner.QueryRow(ctx, `
SELECT count(*)
FROM pg_trigger t
JOIN pg_class c ON c.oid=t.tgrelid
JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public'
  AND c.relname='audit_log'
  AND NOT t.tgisinternal
  AND t.tgenabled IN ('O','A')
  AND (t.tgtype & 16) = 16
  AND ((t.tgtype & 4) = 4 OR (t.tgtype & 8) = 8)`).Scan(&immutableTriggers); err != nil {
		return "", fmt.Errorf("recovery: inspect audit immutability trigger: %w", err)
	}
	if immutableTriggers == 0 {
		return "", fmt.Errorf("recovery: restored audit log has no enabled UPDATE/DELETE immutability trigger")
	}

	return fmt.Sprintf("%d pre-backup audit markers continuous; %d append-only trigger(s) intact; backup=%s restore=%s", len(seam.RequestIDs), immutableTriggers, seam.BackupID, seam.RestoreID), nil
}

// RecordRecoveryEvent appends the recovery decision to the normal immutable audit
// trail under an explicit tenant context. It never updates or replaces history.
func RecordRecoveryEvent(ctx context.Context, app *pgxpool.Pool, tenantID uuid.UUID, actorID *uuid.UUID, actorEmail, backupID, restoreID, result string) error {
	if app == nil || tenantID == uuid.Nil {
		return fmt.Errorf("recovery: audit writer and tenant are required")
	}
	if strings.TrimSpace(backupID) == "" || strings.TrimSpace(restoreID) == "" || strings.TrimSpace(result) == "" {
		return fmt.Errorf("recovery: backup id, restore id, and result are required")
	}
	tx, err := app.Begin(ctx)
	if err != nil {
		return fmt.Errorf("recovery: begin audit event: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenantID.String()); err != nil {
		return fmt.Errorf("recovery: set audit tenant: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO audit_log (actor_id,actor_email,action,target,metadata,request_id)
VALUES ($1,$2,'recovery.certification',$3,jsonb_build_object('backup_id',$4,'restore_id',$5,'result',$6),$7)`,
		actorID, actorEmail, "restore:"+restoreID, backupID, restoreID, result, "recovery:"+restoreID); err != nil {
		return fmt.Errorf("recovery: append audit event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("recovery: commit audit event: %w", err)
	}
	return nil
}
