package soar

// §6.11 slice B — MUST-3 reverse (business-continuity, SOAR-010). Every containment declares its inverse
// (isolate↔release, disable↔enable). Reverse undoes a run's real containment actions in the opposite
// order they were applied — but ONLY the ones that ACTUALLY changed state. The observed prior state was
// captured in Phase B; an action whose prior_state says the target was ALREADY in the end state was a
// no-op, so reversing it would be the landmine the reviewer named (re-enabling an account the customer
// had independently disabled). Those are skipped, audited as skipped.
//
// Convention: an Actioner's Fn returns prior_state including a boolean "changed" — true when the action
// really altered state, false when it found the target already in the end state (a no-op). Reverse acts
// only on changed==true.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ReverseResult reports one step's reverse outcome.
type ReverseResult struct {
	StepIndex int    `json:"step_index"`
	Action    string `json:"action"`
	Status    string `json:"status"` // reversed | skipped_noop | not_reversible | failed
	Detail    string `json:"detail"`
}

// ReverseRun undoes a run's real containment actions (newest first), skipping no-ops. Each reversed action
// invokes the declared inverse Actioner with the connector's vault creds and is audited; the original row
// is flagged reversed. Reverse is intentionally lighter-gated than containment (it restores service and is
// time-critical for business continuity), but every action — reversed OR skipped — is audited.
func (s *Supervisor) ReverseRun(ctx context.Context, tenantID uuid.UUID, actor auth.Principal, runID uuid.UUID) ([]ReverseResult, error) {
	rows, err := s.repo.listReversibleExecutions(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	var creds []byte
	out := make([]ReverseResult, 0, len(rows))
	for i := range rows {
		ex := rows[i]
		res := ReverseResult{StepIndex: ex.StepIndex, Action: ex.ActionKey}

		orig, ok := s.actioners.lookup(ex.ConnectorKey, ex.ActionKey)
		if !ok || !orig.Reversible || orig.Inverse == "" {
			res.Status, res.Detail = "not_reversible", "no declared inverse"
			out = append(out, res)
			continue
		}
		// MUST-3: only undo actions that actually changed state (prior_state.changed == true).
		if changed, _ := ex.PriorState["changed"].(bool); !changed {
			res.Status, res.Detail = "skipped_noop", "original action did not change state (prior_state.changed=false); not reversing"
			s.auditReverse(ctx, tenantID, actor, ex, "skipped_noop", res.Detail)
			out = append(out, res)
			continue
		}
		inv, ok := s.actioners.lookup(ex.ConnectorKey, orig.Inverse)
		if !ok {
			res.Status, res.Detail = "not_reversible", "inverse actioner "+ex.ConnectorKey+":"+orig.Inverse+" not registered"
			out = append(out, res)
			continue
		}
		if s.creds == nil {
			creds = nil
		} else if creds == nil {
			if c, e := s.creds.ConnectorCreds(ctx, tenantID, ex.ConnectorKey); e == nil {
				creds = c
			}
		}
		// Forward the ORIGINAL action's vendor id (prior_state.action_id, the G-1 bare id) to the inverse as
		// `prior_action_id`. Additive: existing inverses (Defender/Entra/Okta/CS-host) ignore it and key off
		// Target. It exists for "delete-what-we-made" inverses — e.g. CrowdStrike cs_allow_hash must delete the
		// EXACT indicator our block created, not merely whatever indicator now matches the hash (which could be a
		// foreign one created after ours). Without this the inverse can only re-find by target, which is a TOCTOU:
		// the `changed=true` gate above proves WE created an indicator, not that the one matching now is ours.
		revParams := map[string]any{"reverse_of": ex.ActionKey}
		if aid, ok := ex.PriorState["action_id"].(string); ok && aid != "" {
			revParams["prior_action_id"] = aid
		}
		ref, _, callErr := safeCall(ctx, inv, creds, ex.Target, revParams)
		if callErr != nil {
			res.Status, res.Detail = "failed", callErr.Error()
			out = append(out, res)
			continue
		}
		// F-L3: the vendor reversal already SUCCEEDED (safeCall above). If the DB mark-reversed + audit write
		// now fails, the reversal happened but the trail is incomplete — that must not be silent. We keep the
		// result "reversed" (the containment IS undone in the vendor) but log it loudly for reconciliation.
		if e := s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
			if e := s.repo.markReversedTx(ctx, tx, ex.ID); e != nil {
				return e
			}
			return audit.Record(ctx, tx, audit.Entry{ActorID: actor.UserID, ActorEmail: actor.Email, Action: "soar.action_reverse",
				Target: "action:" + orig.Inverse, Metadata: map[string]any{"connector": ex.ConnectorKey, "target": ex.Target, "reversed_of": ex.ActionKey, "ref": ref}})
		}); e != nil && s.log != nil {
			s.log.Error("soar reverse: vendor action reversed but mark-reversed/audit write failed (trail incomplete)",
				"execution", ex.ID, "connector", ex.ConnectorKey, "inverse", orig.Inverse, "target", ex.Target, "err", e)
		}
		res.Status, res.Detail = "reversed", "invoked "+orig.Inverse+": "+ref
		out = append(out, res)
	}
	return out, nil
}

func (s *Supervisor) auditReverse(ctx context.Context, tenantID uuid.UUID, actor auth.Principal, ex ActionExecution, status, detail string) {
	if e := s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{ActorID: actor.UserID, ActorEmail: actor.Email, Action: "soar.action_reverse",
			Target: "action:" + ex.ActionKey, Metadata: map[string]any{"connector": ex.ConnectorKey, "target": ex.Target, "status": status, "detail": detail}})
	}); e != nil && s.log != nil {
		// F-L3: a skipped/no-op reverse decision that isn't audited leaves a gap in the containment trail.
		s.log.Error("soar reverse: audit write failed", "execution", ex.ID, "connector", ex.ConnectorKey, "status", status, "err", e)
	}
}
