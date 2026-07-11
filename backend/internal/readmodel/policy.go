package readmodel

import (
	"context"
	"errors"

	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DefaultCustomerVisibleStages is the fail-closed row gate: the "engaged" stages where the provider has
// deliberately involved the customer. Early internal stages (new/triage/assigned/investigating) are withheld.
// MUST stay in sync with the DEFAULT in migrations/0101_disclosure_policy.sql.
var DefaultCustomerVisibleStages = []incident.Stage{
	incident.StageWaitingCustomer, incident.StageContainmentPending, incident.StageContained,
	incident.StageEradication, incident.StageRecovery, incident.StageMonitoring,
	incident.StageClosed, incident.StagePostIncidentReview,
}

// DefaultDisclosurePolicy is the conservative policy used when a tenant has no disclosure_policy row (or on a
// read error). Root cause withheld; only engaged stages visible. A missing row can never mass-disclose.
func DefaultDisclosurePolicy() DisclosurePolicy {
	m := make(map[incident.Stage]bool, len(DefaultCustomerVisibleStages))
	for _, s := range DefaultCustomerVisibleStages {
		m[s] = true
	}
	return DisclosurePolicy{CustomerVisibleStages: m, DiscloseRootCause: false}
}

// validStages is the closed set of lifecycle stages an admin may name in a disclosure policy. Anything else is
// rejected — a garbage stage would silently never match, hiding a misconfiguration.
var validStages = map[string]bool{
	string(incident.StageNew): true, string(incident.StageTriage): true, string(incident.StageAssigned): true,
	string(incident.StageInvestigating): true, string(incident.StageWaitingCustomer): true,
	string(incident.StageContainmentPending): true, string(incident.StageContained): true,
	string(incident.StageEradication): true, string(incident.StageRecovery): true,
	string(incident.StageMonitoring): true, string(incident.StageClosed): true,
	string(incident.StagePostIncidentReview): true,
}

// PolicyStore reads and writes the per-tenant disclosure policy (admin-config). Tenant-scoped via RLS.
type PolicyStore struct{ db *database.DB }

// NewPolicyStore builds the store.
func NewPolicyStore(db *database.DB) *PolicyStore { return &PolicyStore{db: db} }

// Resolve returns the tenant's disclosure policy, or the fail-closed default when no row exists. A DB error also
// returns the default (so a transient read failure fails CLOSED — least disclosure — never open).
func (s *PolicyStore) Resolve(ctx context.Context, tenantID uuid.UUID) (DisclosurePolicy, error) {
	var stages []string
	var discloseRC bool
	found := false
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT customer_visible_stages, disclose_root_cause FROM disclosure_policy WHERE tenant_id=$1`, tenantID)
		if e := row.Scan(&stages, &discloseRC); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return nil // no row → caller uses the default
			}
			return e
		}
		found = true
		return nil
	})
	if err != nil || !found {
		return DefaultDisclosurePolicy(), err
	}
	m := make(map[incident.Stage]bool, len(stages))
	for _, st := range stages {
		m[incident.Stage(st)] = true
	}
	return DisclosurePolicy{CustomerVisibleStages: m, DiscloseRootCause: discloseRC}, nil
}

// SetPolicy upserts the tenant's disclosure policy (admin-config) and audits the change. Stages are validated
// against the closed lifecycle set. This only moves WITHIN the safe envelope: choosing which customer-safe
// stages/fields appear — it can never expose a provider-internal field (the projection struct has none).
func (s *PolicyStore) SetPolicy(ctx context.Context, p auth.Principal, tenantID uuid.UUID, stages []string, discloseRootCause bool) error {
	seen := map[string]bool{}
	clean := make([]string, 0, len(stages))
	for _, st := range stages {
		if !validStages[st] {
			return httpx.ErrBadRequest("unknown incident stage: " + st)
		}
		if !seen[st] {
			seen[st] = true
			clean = append(clean, st)
		}
	}
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO disclosure_policy (id, tenant_id, customer_visible_stages, disclose_root_cause, updated_by)
			 VALUES ($1,$2,$3,$4,$5)
			 ON CONFLICT (tenant_id) DO UPDATE
			   SET customer_visible_stages = EXCLUDED.customer_visible_stages,
			       disclose_root_cause     = EXCLUDED.disclose_root_cause,
			       updated_at              = now(),
			       updated_by              = EXCLUDED.updated_by`,
			uuid.New(), tenantID, clean, discloseRootCause, p.UserID); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "disclosure_policy.set",
			Target:   "tenant:" + tenantID.String(),
			Metadata: map[string]any{"customer_visible_stages": clean, "disclose_root_cause": discloseRootCause},
		})
	})
}
