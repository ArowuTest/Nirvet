package soar

// §6.11 slice B — the step-level supervisor at the RUN level (MUST-2). Once a run involves any real
// connector containment action, the supervisor OWNS THE ENTIRE RUN in strict step order (the reviewer's
// handoff rule): it drives internal steps in-tx (slice-A executor) and connector steps through the
// two-phase engine, one at a time, persisting the run + current_step cursor after EACH step, and NEVER
// advancing past a step that is awaiting or still executing. This is what guarantees ordering — a
// "collect evidence" internal step completes before an "isolate endpoint" connector step. Runs with no
// registered Actioner never reach here (Run/Approve keep the exact slice-A inline path).

import (
	"context"
	"log/slog"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/safe"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// stepDone reports whether a step result is already terminal (so a resume skips it).
func stepDone(status string) bool {
	switch status {
	case StatusExecuted, StatusSimulated, StatusSkipped, StatusFailed, StatusWithheld:
		return true
	}
	return false
}

// runSupervised starts a supervisor-driven run: it inserts the run as 'running' (dedup + advisory lock,
// same idempotency guarantees as the inline path), then drives it. Auto steps start 'pending'; steps
// needing approval keep 'awaiting_approval'.
func (s *Service) runSupervised(ctx context.Context, p auth.Principal, tenantID uuid.UUID, pb *Playbook, plans []stepPlan, incidentID *uuid.UUID) (*PlaybookRun, error) {
	run := &PlaybookRun{ID: uuid.New(), TenantID: tenantID, PlaybookID: pb.ID, IncidentID: incidentID, RequestedBy: &p.UserID, Status: RunRunning}
	var existing *PlaybookRun
	err := s.repo.RunTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if incidentID != nil {
			if e := s.repo.lockRunKeyTx(ctx, tx, pb.ID, *incidentID); e != nil {
				return e
			}
		}
		if ex, e := s.repo.activeRunForTx(ctx, tx, tenantID, pb.ID, incidentID); e != nil {
			return e
		} else if ex != nil {
			existing = ex
			return nil
		}
		for i := range plans {
			sr := plans[i].sr
			if plans[i].auto && sr.Status == "" {
				sr.Status = "pending"
			}
			run.Steps = append(run.Steps, sr)
		}
		if e := s.repo.insertRunTx(ctx, tx, run); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.run_start",
			Target: "playbook:" + pb.ID.String(), Metadata: map[string]any{"status": run.Status, "steps": len(run.Steps), "supervised": true}})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not start run")
	}
	if existing != nil {
		return existing, nil
	}
	s.advanceRun(ctx, p, run, plans, incidentID, 0)
	return run, nil
}

// advanceRun drives a run's steps from `from` in strict order. It persists the run + cursor after each
// step and stops at the first step that needs approval or is left awaiting a human — NEVER advancing past
// an unfinished step. Idempotent/resumable: already-terminal steps are skipped, so it can be re-entered
// from any cursor (crash resume / post-approval).
func (s *Service) advanceRun(ctx context.Context, p auth.Principal, run *PlaybookRun, plans []stepPlan, incidentID *uuid.UUID, from int) {
	anyFailed := false
	i := from
	for ; i < len(plans); i++ {
		if i < len(run.Steps) && stepDone(run.Steps[i].Status) {
			continue // already executed on a prior pass
		}
		pl := plans[i]
		if !pl.auto {
			run.Status = RunPendingApproval
			s.persistRun(ctx, run, i)
			return
		}
		// Class 4 (business_critical) never auto-executes a connector effect in V1 (§9.5) — it becomes a
		// human work-item and the run pauses awaiting the incident-commander + customer.
		if pl.act.RiskClass == RiskBusinessCritical {
			run.Steps[i].Status = StatusAwaitingCustomer
			run.Steps[i].Note = "business_critical: incident-commander + customer authorization required (no autonomous execution in V1)"
			run.Status = RunRunning
			s.persistRun(ctx, run, i)
			return
		}

		var status, note string
		if _, ok := s.actioners.lookup(pl.act.ConnectorKey, pl.act.ActionKey); ok {
			st, nt, err := s.sup.ExecuteConnectorStep(ctx, run.TenantID, p, run.ID, i, pl.act, pl.target, stepParams(incidentID, "", pl.sr.Name))
			if err != nil {
				status, note = StatusFailed, "supervisor error: "+err.Error()
			} else {
				status, note = st, nt
			}
			if status == StatusAwaitingCustomer {
				run.Steps[i].Status, run.Steps[i].Note = status, note
				run.Status = RunRunning
				s.persistRun(ctx, run, i) // pause here — do NOT advance past an awaiting step
				return
			}
		} else {
			// Internal step. Commit its EFFECT, its audit, its terminal STATUS and the cursor advance in ONE tx
			// (audit fix): previously the effect committed here and the status persisted in a SEPARATE tx below, so
			// a crash between them left the effect durably applied while the step stayed non-terminal — ResumeStale
			// then re-dispatched it, double-firing the effect. Connector steps get this crash-safety from their
			// claim-once soar_action_execution row; internal steps had no such guard until now.
			if err := s.repo.RunTx(ctx, run.TenantID, func(ctx context.Context, tx pgx.Tx) error {
				status, note = s.execs.dispatch(ctx, tx, run.TenantID, pl.act, stepParams(incidentID, "", pl.sr.Name))
				if e := audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.action_execute",
					Target: "action:" + pl.act.ActionKey, Metadata: map[string]any{"status": status, "risk": pl.act.RiskClass}}); e != nil {
					return e
				}
				run.Steps[i].Status, run.Steps[i].Note = status, note
				if e := s.repo.updateRunTx(ctx, tx, run); e != nil {
					return e
				}
				return s.repo.setCurrentStepTx(ctx, tx, run.ID, i+1)
			}); err != nil {
				// Effect + status rolled back together — nothing was applied. Record the failure via the shared
				// path below; a later ResumeStale re-drives this step from the unchanged cursor, which is safe.
				status, note = StatusFailed, "internal step aborted: "+err.Error()
			} else {
				if status == StatusFailed {
					anyFailed = true
				}
				continue // effect + status + cursor already committed atomically; move to the next step
			}
		}
		run.Steps[i].Status, run.Steps[i].Note = status, note
		if status == StatusFailed {
			anyFailed = true
		}
		s.persistRun(ctx, run, i+1)
	}
	now := time.Now()
	if anyFailed {
		run.Status = RunFailed
	} else {
		run.Status = RunCompleted
	}
	run.CompletedAt = &now
	s.persistRun(ctx, run, i)
}

// persistRun writes the run's steps/status/completion + the supervisor cursor in one tx.
func (s *Service) persistRun(ctx context.Context, run *PlaybookRun, cursor int) {
	_ = s.repo.RunTx(ctx, run.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if e := s.repo.updateRunTx(ctx, tx, run); e != nil {
			return e
		}
		return s.repo.setCurrentStepTx(ctx, tx, run.ID, cursor)
	})
}

// replan rebuilds resolved step plans for a run being resumed/approved. allAuto=true marks every step
// auto (they already cleared authority to reach running/approved); the per-step Actioner + Class4 guards
// in advanceRun still apply.
func (s *Service) replan(ctx context.Context, tenantID uuid.UUID, pb *Playbook, allAuto bool) []stepPlan {
	plans := make([]stepPlan, 0, len(pb.Steps))
	for _, st := range pb.Steps {
		act, _ := s.repo.resolveAction(ctx, tenantID, st.Action)
		if act.ConnectorKey == "" {
			act.ConnectorKey = st.ConnectorKey
		}
		plans = append(plans, stepPlan{act: act, auto: allAuto, target: st.Target,
			sr: StepResult{Name: st.Name, ConnectorKey: act.ConnectorKey, Action: st.Action, Risk: act.RiskClass}})
	}
	return plans
}

// Reverse undoes a run's real containment actions (MUST-3), honoring observed prior state. Requires the
// supervisor to be wired; the caller is a privileged approver (router-gated).
func (s *Service) Reverse(ctx context.Context, p auth.Principal, runID uuid.UUID) ([]ReverseResult, error) {
	if s.sup == nil {
		return nil, httpx.ErrBadRequest("real containment (and reverse) is not enabled")
	}
	if _, err := s.repo.GetRun(ctx, p.TenantID, runID); err != nil {
		return nil, httpx.ErrNotFound("run not found")
	}
	res, err := s.sup.ReverseRun(ctx, p.TenantID, p, runID)
	if err != nil {
		return nil, httpx.ErrInternal("could not reverse run")
	}
	return res, nil
}

// ResumeRun re-drives a supervisor-owned run from its cursor (skips terminal steps) — used by the
// crash-resume loop. System-invoked (no interactive principal).
func (s *Service) ResumeRun(ctx context.Context, tenantID, runID uuid.UUID) {
	if s.sup == nil {
		return
	}
	run, err := s.repo.GetRun(ctx, tenantID, runID)
	if err != nil || run.Status != RunRunning {
		return
	}
	pb, err := s.repo.GetPlaybook(ctx, tenantID, run.PlaybookID)
	if err != nil {
		return
	}
	plans := s.replan(ctx, tenantID, pb, true)
	s.advanceRun(ctx, auth.Principal{TenantID: tenantID}, run, plans, run.IncidentID, 0)
}

// ResumeStale finds runs stranded with an 'executing' step past the visibility window and re-drives each.
// Returns the number resumed.
func (s *Service) ResumeStale(ctx context.Context, visibilitySecs int) (int, error) {
	if s.sup == nil {
		return 0, nil
	}
	stale, err := s.repo.staleRuns(ctx, visibilitySecs)
	if err != nil {
		return 0, err
	}
	for _, sr := range stale {
		s.ResumeRun(ctx, sr.TenantID, sr.RunID)
	}
	return len(stale), nil
}

// StartResumeLoop re-drives stranded supervisor runs on a ticker until ctx is cancelled (crash recovery).
// Panic-guarded; runs in exactly one process. No-op when the supervisor is not wired.
func (s *Service) StartResumeLoop(ctx context.Context, log *slog.Logger, interval time.Duration, visibilitySecs int) {
	if s.sup == nil {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			safe.Do(log, "soar-resume", func() {
				if n, err := s.ResumeStale(ctx, visibilitySecs); err != nil {
					log.Warn("soar resume-stale failed", "err", err)
				} else if n > 0 {
					log.Warn("soar resumed stranded runs", "count", n)
				}
			})
		}
	}
}
