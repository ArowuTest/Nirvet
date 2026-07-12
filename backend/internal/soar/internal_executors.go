package soar

// #187 slice C — real internal, NON-DESTRUCTIVE executors. The internal action_keys (enrich, create_note,
// create_ticket, add_watchlist, collect_evidence) previously had no live executor and truthfully SIMULATED.
// This backs them with a durable, tenant-scoped record written INSIDE the run's transaction — a real effect,
// but non-destructive by construction (it only writes a tenant-owned row; no outbound, nothing external).
// Destructive/vendor actions are unaffected — they stay on the Actioner registry + destructive_enabled +
// approval. Domain-specific routing (add_watchlist → STIX store, collect_evidence → evidence-pack, create_note
// → incident notes) is #181; this launch slice makes the internal path real and inspectable without importing
// those domains (no import cycle, no cross-domain write surface).

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ListActionRecords returns a tenant's recent internal-action records (management/inspection view).
func (s *Service) ListActionRecords(ctx context.Context, tenantID uuid.UUID, limit int) ([]ActionRecord, error) {
	return s.repo.ListActionRecords(ctx, tenantID, limit)
}

// internalActionKind maps an internal action_key to the record kind it produces. An action not listed here is
// NOT handled by this executor (it stays simulated) — so registering internalRecorder for a key it doesn't know
// is a no-op-safe mistake caught by the "" return.
func internalActionKind(action string) string {
	switch action {
	case "create_note":
		return "note"
	case "create_ticket":
		return "ticket"
	case "add_watchlist":
		return "watchlist"
	case "collect_evidence":
		return "evidence"
	case "enrich":
		return "enrichment"
	default:
		return ""
	}
}

// InternalActionKeys are the internal action_keys backed by internalRecorder (used by main to register it).
func InternalActionKeys() []string {
	return []string{"create_note", "create_ticket", "add_watchlist", "collect_evidence", "enrich"}
}

// internalRecorder is the ActionExecutor for the internal, non-destructive actions. It writes one tenant-owned
// soar_action_records row per step, inside the run's tx (so the effect commits atomically with the run + audit,
// or not at all), and is panic-guarded by safeExecute like any executor.
type internalRecorder struct{ repo *Repository }

// NewInternalRecorder builds the internal-action executor.
func NewInternalRecorder(repo *Repository) ActionExecutor { return &internalRecorder{repo: repo} }

func (x *internalRecorder) Execute(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, action string, params map[string]any) (Outcome, error) {
	kind := internalActionKind(action)
	if kind == "" {
		// Not an action this executor backs → decline to a truthful simulation (dispatch records simulated).
		return Outcome{Executed: false, Detail: "no internal handler for " + action}, nil
	}
	var incidentID *uuid.UUID
	if s, ok := params["incident_id"].(string); ok && s != "" {
		if id, err := uuid.Parse(s); err == nil {
			incidentID = &id
		}
	}
	playbook, _ := params["playbook"].(string)
	step, _ := params["step"].(string)
	summary := kind + " recorded by playbook step '" + step + "'"
	detail := map[string]any{"playbook": playbook, "step": step, "action": action}
	ref, err := x.repo.insertActionRecordTx(ctx, tx, tenantID, incidentID, action, kind, summary, detail)
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Executed: true, Detail: "recorded " + kind + " " + ref}, nil
}

// insertActionRecordTx writes one internal-action record within tx and returns a short human reference (the
// record id's leading segment). RLS + the WithTenant tx pin the row to tenantID; the WITH CHECK also rejects any
// mismatched tenant defensively.
func (r *Repository) insertActionRecordTx(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, incidentID *uuid.UUID, action, kind, summary string, detail map[string]any) (string, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx,
		`INSERT INTO soar_action_records (tenant_id, incident_id, action_key, kind, summary, detail)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		tenantID, incidentID, action, kind, summary, detail).Scan(&id)
	if err != nil {
		return "", err
	}
	return id.String()[:8], nil
}

// ListActionRecords returns a tenant's recent internal-action records (management/inspection view).
func (r *Repository) ListActionRecords(ctx context.Context, tenantID uuid.UUID, limit int) ([]ActionRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []ActionRecord
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, incident_id, action_key, kind, summary, created_at FROM soar_action_records
			  ORDER BY created_at DESC LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a ActionRecord
			if err := rows.Scan(&a.ID, &a.IncidentID, &a.ActionKey, &a.Kind, &a.Summary, &a.CreatedAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
