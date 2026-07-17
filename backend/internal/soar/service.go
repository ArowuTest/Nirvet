package soar

import (
	"context"
	"fmt"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Authorizer resolves the tenant's per-action authority-to-act policy and sets the tenant-wide
// catch-all. Implemented by tenant.Service (single source of truth: authority_policies). SOAR
// consumes this instead of the legacy tenants.authority_mode column (Phase 0 reconciliation).
// ResolveAuthorityDecision returns the FULL policy (mode + approver_role floor + business_hours_only)
// so SOAR can actually enforce the stored controls (Round-4 H2 — they were written but unconsumed).
type Authorizer interface {
	ResolveAuthorityMode(ctx context.Context, tenantID uuid.UUID, actionType string) (string, error)
	ResolveAuthorityDecision(ctx context.Context, tenantID uuid.UUID, actionType string) (mode, approverRole string, businessHoursOnly bool, err error)
	SetCatchAllAuthority(ctx context.Context, actor auth.Principal, tenantID uuid.UUID, mode string) error
}

// Service orchestrates playbook runs under authority-to-act with approval gates.
type Service struct {
	repo      *Repository
	authz     Authorizer
	execs     *Executors
	sup       *Supervisor       // §6.11 slice B: drives real connector containment two-phase (optional)
	actioners *ActionerRegistry // registered real connector actions (empty = none → slice-A behavior)
	validator ApproverValidator // §6.12 #188: re-validate a recorded internal approver is still active (optional)
}

// ApproverValidator re-checks, at execution time, that a recorded internal approver is still an active user — so a
// stale approval (the approver was disabled after approving) cannot fire a destructive action. Optional (nil skips).
type ApproverValidator interface {
	IsActive(ctx context.Context, tenantID, userID uuid.UUID) bool
}

// WithApproverValidator wires the re-validation seam (#188).
func (s *Service) WithApproverValidator(v ApproverValidator) *Service { s.validator = v; return s }

// NewService builds the service. The executor registry starts empty (every action simulates); real
// executors are registered via WithExecutors at wiring time.
func NewService(repo *Repository) *Service {
	return &Service{repo: repo, execs: NewExecutors(), actioners: NewActionerRegistry()}
}

// WithSupervisor wires the slice-B two-phase supervisor + its Actioner registry. A run is supervisor-driven
// only when a step's action has a registered Actioner; with none wired (or none matching), Run/Approve keep
// the exact slice-A inline behavior — so the slice-A suite is unaffected.
func (s *Service) WithSupervisor(sup *Supervisor) *Service {
	if sup != nil {
		s.sup = sup
		s.actioners = sup.actioners
	}
	return s
}

// supervisedNeeded reports whether any planned step is a real connector action (has a registered
// Actioner) — in which case the supervisor owns the whole run in order (the handoff rule).
func (s *Service) supervisedNeeded(plans []stepPlan) bool {
	if s.sup == nil {
		return false
	}
	for i := range plans {
		if _, ok := s.actioners.lookup(plans[i].act.ConnectorKey, plans[i].act.ActionKey); ok {
			return true
		}
	}
	return false
}

// WithAuthorizer wires the per-action authority store (tenant.Service, the single source of truth:
// authority_policies). Always wired in production; a nil authorizer resolves fail-closed to 'observe'
// (nothing auto-runs). The legacy tenants.authority_mode column was dropped (Round-4 hygiene).
func (s *Service) WithAuthorizer(a Authorizer) *Service { s.authz = a; return s }

// WithExecutors wires the action-executor registry (real dispatch for registered actions; unregistered
// actions simulate). Passing nil resets to an empty registry rather than nil-panicking on dispatch.
func (s *Service) WithExecutors(e *Executors) *Service {
	if e == nil {
		e = NewExecutors()
	}
	s.execs = e
	return s
}

// stepParams builds the parameter map handed to an executor for a step.
func stepParams(incidentID *uuid.UUID, playbook, step string) map[string]any {
	m := map[string]any{"playbook": playbook, "step": step}
	if incidentID != nil {
		m["incident_id"] = incidentID.String()
	}
	return m
}

var validModes = map[AuthorityMode]bool{
	AuthorityObserve: true, AuthorityApproval: true, AuthorityPreAuth: true, AuthorityContractualAuto: true,
}

// resolveDecision returns the effective authority mode + approver-role floor + business-hours-only
// flag for an action (per-action SOAR-003 granularity). Falls back to the legacy tenant-wide mode
// (no floor) when no authorizer is wired (unit tests).
func (s *Service) resolveDecision(ctx context.Context, tenantID uuid.UUID, actionType string) (mode AuthorityMode, approverRole string, businessHours bool, err error) {
	if s.authz != nil {
		m, ar, bh, e := s.authz.ResolveAuthorityDecision(ctx, tenantID, actionType)
		return AuthorityMode(m), ar, bh, e
	}
	return AuthorityObserve, "", false, nil // fail-closed: no authorizer wired ⇒ nothing auto-runs
}

// authDecision is the resolved authority for one action key (mode + approver floor + business-hours flag),
// cached per run so resolveDecision is called once per DISTINCT action, not once per step.
type authDecision struct {
	mode          AuthorityMode
	approverRole  string
	businessHours bool
}

// resolveDecisionsFor resolves the authority decision once per DISTINCT action key (dedup) — hoisting
// resolveDecision out of the per-step loop (the N+1 the reviewer flagged). Identical per-key semantics to
// resolveDecision; a nil/empty keys list yields an empty map.
func (s *Service) resolveDecisionsFor(ctx context.Context, tenantID uuid.UUID, keys []string) (map[string]authDecision, error) {
	out := make(map[string]authDecision, len(keys))
	for _, k := range keys {
		if _, done := out[k]; done {
			continue
		}
		mode, approverRole, bh, err := s.resolveDecision(ctx, tenantID, k)
		if err != nil {
			return nil, err
		}
		out[k] = authDecision{mode: mode, approverRole: approverRole, businessHours: bh}
	}
	return out, nil
}

// distinctStepActions returns the distinct action keys across a playbook's steps (order-preserving).
func distinctStepActions(steps []Step) []string {
	seen := make(map[string]bool, len(steps))
	out := make([]string, 0, len(steps))
	for _, st := range steps {
		if !seen[st.Action] {
			seen[st.Action] = true
			out = append(out, st.Action)
		}
	}
	return out
}

// requiredApproverRank is the minimum approver seniority (auth.RoleRank) to clear a step of the given
// §9.5 risk class: the HIGHER of a risk-scaled default (medium→analyst_t3, high→soc_manager) and the
// tenant-configured approver_role floor (H2 — the stored control is now enforced). business_critical
// is handled separately (never cleared by standard approval in this slice). Uses the canonical role
// rank in auth so this floor and the break-glass tier-cap share one ordering.
func requiredApproverRank(risk RiskClass, configuredApproverRole string) int {
	base := 0
	switch risk {
	case RiskMedium:
		base = auth.RoleRank(auth.RoleAnalystT3)
	case RiskHigh:
		base = auth.RoleRank(auth.RoleSOCManager)
	}
	if configuredApproverRole != "" {
		if r := auth.RoleRank(auth.Role(configuredApproverRole)); r > base {
			base = r
		}
	}
	return base
}

// SetAuthority sets the tenant-wide catch-all authority-to-act mode (POST /soar/authority is a
// convenience over the per-action policy API; it upserts the '*' policy).
func (s *Service) SetAuthority(ctx context.Context, p auth.Principal, tenantID uuid.UUID, mode AuthorityMode) error {
	if !validModes[mode] {
		return httpx.ErrBadRequest("invalid authority mode")
	}
	if s.authz == nil {
		return httpx.ErrInternal("authority store not configured")
	}
	if err := s.authz.SetCatchAllAuthority(ctx, p, tenantID, string(mode)); err != nil {
		return httpx.ErrInternal("could not set authority")
	}
	return nil
}

// ListPlaybooks returns available playbooks.
func (s *Service) ListPlaybooks(ctx context.Context, tenantID uuid.UUID) ([]Playbook, error) {
	return s.repo.ListPlaybooks(ctx, tenantID)
}

// ListRuns returns recent runs.
func (s *Service) ListRuns(ctx context.Context, tenantID uuid.UUID) ([]PlaybookRun, error) {
	return s.repo.ListRuns(ctx, tenantID)
}

// GetRun returns a run.
func (s *Service) GetRun(ctx context.Context, tenantID, id uuid.UUID) (*PlaybookRun, error) {
	run, err := s.repo.GetRun(ctx, tenantID, id)
	if err != nil {
		return nil, httpx.ErrNotFound("run not found")
	}
	return run, nil
}

// stepPlan is a resolved step decided in Run's read phase (no side effects yet).
type stepPlan struct {
	act            ActionCatalog
	auto           bool   // may auto-execute now (permitted by authority, no approval, in-hours)
	target         string // entity a connector step acts on (slice B)
	sr             StepResult
	cond           *StepCondition // #187 slice B: prior-outcome gate (inline path only; skip-only)
	continueOnFail bool           // #187 slice B: keep running after THIS step's execution failure
}

// Run starts a playbook against an incident for the caller's OWN tenant (the standard single-tenant path).
// Thin delegator to runFor with tenantID = p.TenantID — behaviour is unchanged.
func (s *Service) Run(ctx context.Context, p auth.Principal, playbookID uuid.UUID, incidentID *uuid.UUID) (*PlaybookRun, error) {
	return s.runFor(ctx, p, p.TenantID, playbookID, incidentID)
}

// RunForTarget starts a playbook against ANOTHER tenant — the fleet cross-tenant containment path (a fleet
// operator firing a playbook on a customer/agency's alert). The actor stays the OPERATOR (identity → audit,
// Role → approver rank), but EVERY tenant-keyed authority/resource seam — playbook, action catalog + §9.5
// risk class, authority mode + approver floor, run tenant, tx, idempotency, dispatch, AND the two-phase
// supervisor's destructive gate (destructive_enabled / rate-cap / D5 protected-target) — resolves in the
// TARGET tenant. So an operator "acts across the fleet WITHIN each tenant's own rules", never with a
// global capability. It is a PRIMITIVE: the caller MUST have already resolved + fleet-scope-checked
// targetTenant FROM THE RESOURCE (fleet.ResolveTargetTenant) — this method is not itself the BOLA gate.
// Returns (runID, status) so a cross-package caller need not import the run type.
func (s *Service) RunForTarget(ctx context.Context, operator auth.Principal, targetTenant, playbookID uuid.UUID, incidentID *uuid.UUID) (uuid.UUID, string, error) {
	run, err := s.runFor(ctx, operator, targetTenant, playbookID, incidentID)
	if err != nil {
		return uuid.Nil, "", err
	}
	return run.ID, string(run.Status), nil
}

// runFor is the shared core of Run/RunForTarget. It resolves each step's §9.5 risk class + authority in a
// read phase, then dispatches permitted steps and persists the run + audit in ONE transaction (Round-4 M2:
// effect + audit atomic), deduped per (playbook, incident) (M3). Steps needing approval leave the run
// pending_approval. The EXPLICIT tenantID is the resource/authority tenant (own tenant for Run, the resolved
// target for RunForTarget); `p` supplies the actor identity only (p.UserID/p.Email → audit; p.Role → floor).
func (s *Service) runFor(ctx context.Context, p auth.Principal, tenantID, playbookID uuid.UUID, incidentID *uuid.UUID) (*PlaybookRun, error) {
	pb, err := s.repo.GetPlaybook(ctx, tenantID, playbookID)
	if err != nil {
		return nil, httpx.ErrNotFound("playbook not found")
	}

	// Phase 1 — reads only, no side effects: resolve catalog + authority ONCE per run (was per step = an N+1
	// of a WithTenant tx + an authority read per step), then decide auto-run per step from the maps.
	actMap, aerr := s.repo.resolveActionCatalogMap(ctx, tenantID)
	if aerr != nil {
		return nil, httpx.ErrInternal("could not read action catalog")
	}
	decMap, derr := s.resolveDecisionsFor(ctx, tenantID, distinctStepActions(pb.Steps))
	if derr != nil {
		return nil, httpx.ErrInternal("could not read authority-to-act")
	}
	plans := make([]stepPlan, 0, len(pb.Steps))
	for _, st := range pb.Steps {
		// Risk class comes from the admin-configurable action catalog (§9.5), NOT the step JSON — an
		// action absent from the catalog fails closed to business_critical (max approval).
		act := lookupAction(actMap, st.Action)
		if act.ConnectorKey == "" {
			act.ConnectorKey = st.ConnectorKey
		}
		dec := decMap[st.Action]
		mode, businessHours := dec.mode, dec.businessHours
		// business_hours_only fails closed to approval: we cannot yet verify the tenant's business-hours
		// calendar, so an hours-restricted action never auto-runs (Round-4 H2 — consume the stored flag).
		//
		// FleetWide (owner decision, Option 1) — the BREADTH gate. `!act.FleetWide` short-circuits BEFORE the
		// mode-dependent Allowed(...), so a fleet-wide action (blocks a hash/IP/domain across EVERY endpoint) is
		// never auto-eligible under ANY authority mode — pre_authorized/contractual_auto/emergency included. A
		// permissive config must never license a fleet-wide effect (same floor as D5). It routes to
		// awaiting_approval, NOT skipped: a manager can still approve-and-run it, so the control stays REACHABLE
		// (not the business_critical phantom). This line is the ONLY auto-eligibility computation in the codebase,
		// and BOTH run-creation paths reach it (Run→runFor; FireContainment→RunForTarget→runFor), so there is no
		// second decision point to bypass it.
		autoEligible := !st.RequiresApproval && !act.FleetWide && Allowed(mode, act.RiskClass)
		sr := StepResult{Name: st.Name, ConnectorKey: act.ConnectorKey, Action: st.Action, Risk: act.RiskClass}
		if !autoEligible {
			sr.Status = StatusAwaitingApproval
			if act.FleetWide {
				sr.Note = fmt.Sprintf("fleet-wide: approval required regardless of authority mode (class %s, authority '%s')", act.RiskClass, mode)
			} else {
				sr.Note = fmt.Sprintf("requires approval (class %s, authority '%s')", act.RiskClass, mode)
			}
		} else if businessHours {
			sr.Status = StatusAwaitingApproval
			sr.Note = fmt.Sprintf("business-hours-only: deferred to approval (class %s, authority '%s')", act.RiskClass, mode)
		}
		plans = append(plans, stepPlan{act: act, auto: autoEligible && !businessHours, target: st.Target, sr: sr,
			cond: st.Condition, continueOnFail: st.ContinueOnFailure})
	}

	// §6.11 slice B: if any step is a real connector containment action (registered Actioner), the
	// supervisor owns the whole run in order (two-phase). Otherwise keep the exact slice-A inline path.
	if s.supervisedNeeded(plans) {
		return s.runSupervised(ctx, p, tenantID, pb, plans, incidentID)
	}

	// Phase 2 — one tx: idempotency check, dispatch permitted steps, persist run + audit atomically.
	run := &PlaybookRun{ID: uuid.New(), TenantID: tenantID, PlaybookID: pb.ID, IncidentID: incidentID, RequestedBy: &p.UserID}
	var existing *PlaybookRun
	err = s.repo.RunTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Round-4 R-1 (concurrent fully-auto): serialise concurrent Runs for the same (playbook,
		// incident) with a tx-scoped advisory lock, so the idempotency check below can't be raced by a
		// second run whose terminal-status insert the 0038 partial index doesn't cover. Released at tx end.
		if incidentID != nil {
			if e := s.repo.lockRunKeyTx(ctx, tx, pb.ID, *incidentID); e != nil {
				return e
			}
		}
		if ex, e := s.repo.activeRunForTx(ctx, tx, tenantID, pb.ID, incidentID); e != nil {
			return e
		} else if ex != nil {
			existing = ex // M3: a retried run returns the existing active run, no re-dispatch
			return nil
		}
		needsApproval, anyFailed, halted := false, false, false
		for i := range plans {
			pl := &plans[i]
			switch {
			case halted:
				// #187 slice B: a prior step failed and did not continue-on-failure → the run halted; every later
				// step is recorded skipped (not run). A skipped destructive step is skipped, never executed.
				pl.sr.Status = StatusSkipped
				pl.sr.Note = "run halted: a prior step failed"
			case !conditionMet(run.Steps, pl.cond):
				// #187 slice B: prior-outcome gate unmet → skip this step (skip-only; never escalates).
				pl.sr.Status = StatusSkipped
				pl.sr.Note = "skipped: condition not met"
			case pl.auto:
				pl.sr.Status, pl.sr.Note = s.execs.dispatch(ctx, tx, tenantID, pl.act, stepParams(incidentID, pb.Name, pl.sr.Name))
				if pl.sr.Status == StatusFailed {
					anyFailed = true
					if !pl.continueOnFail {
						halted = true // default stop-on-failure (EXECUTION failure only — never an approval denial)
					}
				}
				if e := audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.action_execute",
					Target: "action:" + pl.sr.Action, Metadata: map[string]any{"status": pl.sr.Status, "risk": pl.sr.Risk}}); e != nil {
					return e
				}
			default:
				needsApproval = true
			}
			run.Steps = append(run.Steps, pl.sr)
		}
		switch {
		case needsApproval:
			run.Status = RunPendingApproval
		case anyFailed:
			run.Status = RunFailed
			now := time.Now()
			run.CompletedAt = &now
		default:
			run.Status = RunCompleted
			now := time.Now()
			run.CompletedAt = &now
		}
		if e := s.repo.insertRunTx(ctx, tx, run); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.run_start",
			Target: "playbook:" + pb.ID.String(), Metadata: map[string]any{"status": run.Status, "steps": len(run.Steps)}})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not start run")
	}
	if existing != nil {
		return existing, nil
	}
	return run, nil
}

// canApprove enforces separation of duties: the user who requested a run may not
// approve it. A run with no recorded requester (system/correlation-initiated) may
// be approved by any authorised approver. This is a pure guard so it can be unit
// tested without a database (SRS §6.11; four-eyes on authority-to-act).
func canApprove(run *PlaybookRun, approver uuid.UUID) error {
	if run.RequestedBy != nil && *run.RequestedBy == approver {
		return httpx.ErrForbidden("separation of duties: the requester of a playbook run may not approve it")
	}
	return nil
}

// approvedStep is a pending step cleared for dispatch in Approve's authorization phase.
type approvedStep struct {
	idx            int
	act            ActionCatalog
	block          bool           // business_critical — never executed by standard approval (§9.5)
	cond           *StepCondition // #187 slice B: prior-outcome gate (inline path only)
	continueOnFail bool           // #187 slice B
}

// Approve executes the awaiting steps of a pending run. It RE-RESOLVES risk + authority per step and
// enforces the approver-role floor scaled to §9.5 risk class + the tenant-configured approver_role
// (Round-4 H2 — previously ignored, one approval green-lit every pending step). business_critical
// steps are never cleared here (they need incident-commander + customer authorization not modelled in
// this slice) — they are recorded skipped, fail-closed. Dispatch + audit run in one tx (M2).
func (s *Service) Approve(ctx context.Context, p auth.Principal, runID uuid.UUID) (*PlaybookRun, error) {
	return s.approveFor(ctx, p, p.TenantID, runID)
}

// ApproveForTarget approves a cross-tenant fleet run: an operator approves a pending run that a fleet
// containment left awaiting approval in the TARGET tenant. Four-eyes still bites (the operator who
// requested the run may not approve it — canApprove keys on requester≠approver, both operator UserIDs),
// and the approver floor is the operator-approver's own rank (p.Role) measured against the requirement
// read from the TARGET tenant's authority policy. The caller MUST have fleet-scope-resolved targetTenant
// from the run's resource first (this is a primitive, not the BOLA gate). Returns (runID, status).
func (s *Service) ApproveForTarget(ctx context.Context, operator auth.Principal, targetTenant, runID uuid.UUID) (uuid.UUID, string, error) {
	run, err := s.approveFor(ctx, operator, targetTenant, runID)
	if err != nil {
		return uuid.Nil, "", err
	}
	return run.ID, string(run.Status), nil
}

// approveFor is the shared core of Approve/ApproveForTarget. It re-resolves risk + authority per step and
// enforces the approver-role floor (scaled to §9.5 risk + the tenant-configured approver_role) BEFORE any
// step executes. The EXPLICIT tenantID is the run's tenant (own for Approve, the resolved target for the
// fleet path); `p` supplies the approver identity (p.UserID → four-eyes/audit; p.Role → floor rank).
func (s *Service) approveFor(ctx context.Context, p auth.Principal, tenantID, runID uuid.UUID) (*PlaybookRun, error) {
	run, err := s.repo.GetRun(ctx, tenantID, runID)
	if err != nil {
		return nil, httpx.ErrNotFound("run not found")
	}
	if run.Status != RunPendingApproval {
		return nil, httpx.ErrBadRequest("run is not pending approval")
	}
	// Four-eyes: an approver cannot rubber-stamp their own requested action.
	if err := canApprove(run, p.UserID); err != nil {
		return nil, err
	}

	// #187 slice B: control-flow (condition/continue_on_failure) lives on the playbook step, not the recorded
	// StepResult — map it by name so the approve execution loop can honor it. Conditions only exist in all-inline
	// playbooks (the authoring boundary forbids them alongside a connector step), so this path always honors them.
	cf := map[string]Step{}
	if pb, perr := s.repo.GetPlaybook(ctx, tenantID, run.PlaybookID); perr == nil {
		for _, st := range pb.Steps {
			cf[st.Name] = st
		}
	}

	// #188 customer-approval gate. Default (platform_analyst) runs the historical path unchanged. customer_approver
	// / both_required record this internal approval and only EXECUTE once the policy's required set of distinct
	// principals is present (never customer-alone; business_critical is never executed here — it stays skipped).
	policy := s.resolveCustomerPolicy(ctx, tenantID)
	if policy.Authority != AuthorityPlatformAnalyst {
		if err := s.recordApproval(ctx, tenantID, run.ID, approvalInternal, &p.UserID, p.Email, string(p.Role)); err != nil {
			return nil, httpx.ErrInternal("could not record approval")
		}
		ready, execP, ea, gerr := s.evaluateGate(ctx, tenantID, run, policy)
		if gerr != nil {
			return nil, gerr
		}
		if !ready {
			return run, nil // internal approval recorded; the run stays pending until the customer approves
		}
		return s.executeRun(ctx, execP, tenantID, run, cf, ea)
	}
	return s.executeRun(ctx, p, tenantID, run, cf, execAuth{})
}

// executeRun runs the authorization + (supervised or inline) execution phases for an approved run, acting as
// `execP`. `ea` carries the #188 customer-approval context: `skipInternalRank` means a customer's tenant-delegated
// authorization stands in for the platform approver-rank floor on non-business_critical steps. business_critical
// steps are NEVER executed here — they stay skipped (fail-safe); customer-approval covers high-risk destructive
// actions, and the extreme business_critical class needs the incident-commander flow (out of scope).
func (s *Service) executeRun(ctx context.Context, execP auth.Principal, tenantID uuid.UUID, run *PlaybookRun, cf map[string]Step, ea execAuth) (*PlaybookRun, error) {
	// Authorization phase (no side effects): re-resolve each pending step and check the approver floor
	// BEFORE executing any step, so a too-junior approver is rejected without partial execution.
	// Resolve the catalog ONCE, and (only when the platform approver-rank floor applies) the authority decisions
	// for the pending steps' distinct actions ONCE — hoisting resolveAction/resolveDecision out of the per-step
	// loop (the N+1). A customer authorization (skipInternalRank) needs no decisions at all.
	actMap, aerr := s.repo.resolveActionCatalogMap(ctx, tenantID)
	if aerr != nil {
		return nil, httpx.ErrInternal("could not read action catalog")
	}
	var decMap map[string]authDecision
	if !ea.skipInternalRank {
		var pendingKeys []string
		for i := range run.Steps {
			if run.Steps[i].Status == StatusAwaitingApproval {
				pendingKeys = append(pendingKeys, run.Steps[i].Action)
			}
		}
		var derr error
		if decMap, derr = s.resolveDecisionsFor(ctx, tenantID, pendingKeys); derr != nil {
			return nil, httpx.ErrInternal("could not read authority-to-act")
		}
	}
	var steps []approvedStep
	for i := range run.Steps {
		if run.Steps[i].Status != StatusAwaitingApproval {
			continue
		}
		act := lookupAction(actMap, run.Steps[i].Action)
		if act.ConnectorKey == "" {
			act.ConnectorKey = run.Steps[i].ConnectorKey
		}
		cfStep := cf[run.Steps[i].Name]
		if act.RiskClass == RiskBusinessCritical {
			steps = append(steps, approvedStep{idx: i, act: act, block: true, cond: cfStep.Condition, continueOnFail: cfStep.ContinueOnFailure})
			continue
		}
		// Non-BC: the platform approver-rank floor applies UNLESS a customer authorized this run (customer_approver
		// mode — the tenant delegated authority to the customer approver, so no platform rank is required).
		if !ea.skipInternalRank {
			approverRole := decMap[run.Steps[i].Action].approverRole
			if auth.RoleRank(execP.Role) < requiredApproverRank(act.RiskClass, approverRole) {
				return nil, httpx.ErrForbidden(fmt.Sprintf("approver role '%s' is insufficient to approve a %s-risk action", execP.Role, act.RiskClass))
			}
		}
		steps = append(steps, approvedStep{idx: i, act: act, cond: cfStep.Condition, continueOnFail: cfStep.ContinueOnFailure})
	}

	// §6.11 slice B: a supervised run (any registered connector Actioner) resumes through the two-phase
	// supervisor from its cursor after approval, instead of inline dispatch. The approver-floor check
	// above still gates it; claim-then-act still serialises concurrent approves.
	if pb, perr := s.repo.GetPlaybook(ctx, tenantID, run.PlaybookID); perr == nil {
		plans := s.replan(ctx, tenantID, pb, true)
		if s.supervisedNeeded(plans) {
			claimed := false
			if e := s.repo.RunTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
				ok, ce := s.repo.claimPendingTx(ctx, tx, run.ID)
				if ce != nil {
					return ce
				}
				if !ok {
					return nil
				}
				claimed = true
				return audit.Record(ctx, tx, audit.Entry{ActorID: execP.UserID, ActorEmail: execP.Email, Action: "soar.run_approve",
					Target: "run:" + run.ID.String(), Metadata: map[string]any{"supervised": true}})
			}); e != nil {
				return nil, httpx.ErrInternal("could not approve run")
			}
			if !claimed {
				return nil, httpx.ErrConflict("run is no longer pending approval (already decided)")
			}
			if execP.UserID != uuid.Nil {
				run.ApprovedBy = &execP.UserID
			}
			run.Status = RunRunning
			s.advanceRun(ctx, execP, run, plans, run.IncidentID, 0)
			return run, nil
		}
	}

	// Execution phase (one tx): CLAIM the run (pending_approval→running) before dispatching, so two
	// concurrent approves can't both execute (Round-4 R-2 claim-then-act — the row lock serialises
	// them and the loser sees status≠pending_approval). Then dispatch, persist, audit.
	claimed := false
	err := s.repo.RunTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ok, e := s.repo.claimPendingTx(ctx, tx, run.ID)
		if e != nil {
			return e
		}
		if !ok {
			return nil // another approver claimed it first — nothing dispatched
		}
		claimed = true
		anyFailed, halted := false, false
		for _, st := range steps {
			if halted {
				run.Steps[st.idx].Status = StatusSkipped
				run.Steps[st.idx].Note = "run halted: a prior step failed"
				continue
			}
			if st.block {
				run.Steps[st.idx].Status = StatusSkipped
				run.Steps[st.idx].Note = "business_critical requires incident-commander + customer authorization (not available in this flow)"
				continue
			}
			// #187 slice B: prior-outcome gate against results produced so far (incl. steps already run in phase 2).
			if !conditionMet(run.Steps, st.cond) {
				run.Steps[st.idx].Status = StatusSkipped
				run.Steps[st.idx].Note = "skipped: condition not met"
				continue
			}
			status, note := s.execs.dispatch(ctx, tx, tenantID, st.act, stepParams(run.IncidentID, "", run.Steps[st.idx].Name))
			run.Steps[st.idx].Status = status
			run.Steps[st.idx].Note = note + " (approved by " + execP.Email + ")"
			if status == StatusFailed {
				anyFailed = true
				if !st.continueOnFail {
					halted = true // stop-on-failure (EXECUTION failure only — a denied approval already halts via Reject)
				}
			}
			if e := audit.Record(ctx, tx, audit.Entry{ActorID: execP.UserID, ActorEmail: execP.Email, Action: "soar.action_execute",
				Target: "action:" + run.Steps[st.idx].Action, Metadata: map[string]any{"status": status, "risk": st.act.RiskClass, "approved": true}}); e != nil {
				return e
			}
		}
		if execP.UserID != uuid.Nil {
			run.ApprovedBy = &execP.UserID
		}
		if anyFailed {
			run.Status = RunFailed
		} else {
			run.Status = RunCompleted
		}
		now := time.Now()
		run.CompletedAt = &now
		if e := s.repo.updateRunTx(ctx, tx, run); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: execP.UserID, ActorEmail: execP.Email, Action: "soar.run_approve",
			Target: "run:" + run.ID.String(), Metadata: map[string]any{"status": run.Status}})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not approve run")
	}
	if !claimed {
		return nil, httpx.ErrConflict("run is no longer pending approval (already decided)")
	}
	return run, nil
}

// Reject rejects a pending run without executing further. Like Approve it CLAIMS the run in-tx
// (Round-4 residual: a concurrent Approve+Reject on one run must be serialised — the loser gets 409,
// so a run can't be both approved and rejected).
func (s *Service) Reject(ctx context.Context, p auth.Principal, runID uuid.UUID) (*PlaybookRun, error) {
	return s.rejectFor(ctx, p, p.TenantID, runID)
}

// RejectForTarget rejects a pending cross-tenant fleet run: any authorized operator may CANCEL a containment
// an operator earlier fired but that is still awaiting approval (unlike Approve, reject is fail-safe — nothing
// executes — so it needs no four-eyes; a second operator who disagrees can cancel it). The run's TARGET tenant
// is the explicit param (the caller fleet-scope-resolved it from the alert). Returns (runID, status).
func (s *Service) RejectForTarget(ctx context.Context, operator auth.Principal, targetTenant, runID uuid.UUID) (uuid.UUID, string, error) {
	run, err := s.rejectFor(ctx, operator, targetTenant, runID)
	if err != nil {
		return uuid.Nil, "", err
	}
	return run.ID, string(run.Status), nil
}

// rejectFor is the shared core of Reject/RejectForTarget. tenantID is the run's tenant (own for Reject, the
// resolved target for the fleet path); `p` supplies the actor identity for the audit + rejection note.
func (s *Service) rejectFor(ctx context.Context, p auth.Principal, tenantID, runID uuid.UUID) (*PlaybookRun, error) {
	run, err := s.repo.GetRun(ctx, tenantID, runID)
	if err != nil {
		return nil, httpx.ErrNotFound("run not found")
	}
	if run.Status != RunPendingApproval {
		return nil, httpx.ErrBadRequest("run is not pending approval")
	}
	claimed := false
	err = s.repo.RunTx(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ok, e := s.repo.claimPendingTx(ctx, tx, run.ID)
		if e != nil {
			return e
		}
		if !ok {
			return nil // a concurrent Approve/Reject claimed it first
		}
		claimed = true
		for i := range run.Steps {
			if run.Steps[i].Status == StatusAwaitingApproval {
				run.Steps[i].Status = StatusSkipped
				run.Steps[i].Note = "rejected by " + p.Email
			}
		}
		run.ApprovedBy = &p.UserID
		run.Status = RunRejected
		now := time.Now()
		run.CompletedAt = &now
		if e := s.repo.updateRunTx(ctx, tx, run); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.run_reject",
			Target: "run:" + run.ID.String()})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not reject run")
	}
	if !claimed {
		return nil, httpx.ErrConflict("run is no longer pending approval (already decided)")
	}
	return run, nil
}
