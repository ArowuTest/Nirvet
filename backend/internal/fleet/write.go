package fleet

// The fleet WRITE path — an operator acting on another tenant's alert from the cross-tenant queue. Every write
// follows the same shape, which is the reviewer's MA-2/3 spec:
//   #1/#2  resolve the TARGET tenant from the RESOURCE and check it is in the operator's fleet scope
//          (ResolveTargetTenant — refuses out-of-scope / non-provider / forged id);
//   #4     perform the mutation under WithTenant(target) (via the reused alert service), then record a
//          DEDICATED audit entry in the TARGET tenant with the OPERATOR's real identity — NOT a synthetic
//          principal, and NOT the auditMut middleware (which records under the operator's OWN tenant, so the
//          agency would never see who acted on its resource).
// Destructive SOAR (#3 per-target authority in the target's context, #5 fire-time re-check) is built on this
// same target-resolution foundation in the next unit.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AlertWriter is the subset of the alert service the fleet write path reuses. Each method takes the tenant it
// acts under (here, the resolved TARGET tenant), so the mutation lands in the target tenant's data.
type AlertWriter interface {
	Assign(ctx context.Context, tenantID, id, assignee uuid.UUID) error
	Disposition(ctx context.Context, tenantID, id uuid.UUID, disposition, reason string, by uuid.UUID) error
	// The *Tx variants run a caller-supplied post-mutation callback in the SAME transaction as the mutation, so the
	// fleet write path can land its cross-tenant audit atomically with the assign/disposition (see AssignAlert).
	AssignTx(ctx context.Context, tenantID, id, assignee uuid.UUID, postTx func(ctx context.Context, tx pgx.Tx) error) error
	DispositionTx(ctx context.Context, tenantID, id uuid.UUID, disposition, reason string, by uuid.UUID, postTx func(ctx context.Context, tx pgx.Tx) error) error
}

// ContainmentRunner is the subset of the SOAR service the fleet DESTRUCTIVE path routes through. Both methods
// take an EXPLICIT targetTenant (the resolved target) distinct from the operator actor — so the whole authority
// chain (destructive_enabled gate, §9.5 risk class, approver floor, rate-cap, D5 protected-target) and the
// durable two-phase effect+audit resolve in the TARGET tenant, while the operator supplies identity + approver
// rank. This is why the destructive action goes through SOAR's supervisor (durable, atomic effect+audit landing
// in the target) rather than the best-effort assign/disposition audit shape. *soar.Service satisfies it.
type ContainmentRunner interface {
	RunForTarget(ctx context.Context, operator auth.Principal, targetTenant, playbookID uuid.UUID, incidentID *uuid.UUID) (uuid.UUID, string, error)
	ApproveForTarget(ctx context.Context, operator auth.Principal, targetTenant, runID uuid.UUID) (uuid.UUID, string, error)
	RejectForTarget(ctx context.Context, operator auth.Principal, targetTenant, runID uuid.UUID) (uuid.UUID, string, error)
}

// AssignAlert assigns a fleet alert to an analyst. Target resolved from the resource + scope-checked (#1/#2);
// mutation under the target tenant; audited in the target tenant with the operator's identity (#4).
func (s *Service) AssignAlert(ctx context.Context, p auth.Principal, alertID, assignee uuid.UUID) error {
	target, err := s.ResolveTargetTenant(ctx, p, alertID)
	if err != nil {
		return err
	}
	if s.alerts == nil {
		return httpx.ErrInternal("fleet write path not configured")
	}
	// Mutation + target-tenant audit commit in ONE tx: the audit callback runs inside the assign's transaction
	// (already under WithTenant(target)), so the agency's "who acted on my resource" row can never be dropped
	// while the assignment lands. Previously the two were separate txs — an audit failure left an un-attributed
	// cross-tenant write.
	return s.alerts.AssignTx(ctx, target, alertID, assignee,
		s.auditCallback(p, "fleet.alert.assign", alertID, map[string]any{"assignee": assignee.String()}))
}

// DispositionAlert dispositions a fleet alert (close with a verdict). Same target-resolution + scope check +
// target-tenant audit; the actor (`by`) passed to the alert service is the OPERATOR (never synthesised).
func (s *Service) DispositionAlert(ctx context.Context, p auth.Principal, alertID uuid.UUID, disposition, reason string) error {
	target, err := s.ResolveTargetTenant(ctx, p, alertID)
	if err != nil {
		return err
	}
	if s.alerts == nil {
		return httpx.ErrInternal("fleet write path not configured")
	}
	// Disposition + target-tenant audit in ONE tx (see AssignAlert) — the verdict and its cross-tenant attribution
	// commit together or not at all.
	return s.alerts.DispositionTx(ctx, target, alertID, disposition, reason, p.UserID,
		s.auditCallback(p, "fleet.alert.disposition", alertID, map[string]any{"disposition": disposition}))
}

// FireContainment fires a SOAR containment playbook on another tenant's alert — the highest-consequence fleet
// action (a wrong target = a containment on the wrong government agency). It resolves the TARGET tenant FROM
// THE ALERT (#1/#2 gate — refuses out-of-scope / non-provider / forged id, so a pure oversight/customer
// principal has NO destructive path at all), then hands off to the SOAR supervisor via RunForTarget. The
// authority to act (destructive_enabled, §9.5 risk class, approver floor, rate-cap, D5 protected-target) is
// re-evaluated in the TARGET tenant's context at fire time, and the effect + audit land atomically & durably
// in the target — NOT this package's best-effort audit. The operator is the actor throughout (identity +
// approver rank), never a synthetic principal. Returns (runID, status).
func (s *Service) FireContainment(ctx context.Context, p auth.Principal, alertID, playbookID uuid.UUID, incidentID *uuid.UUID) (uuid.UUID, string, error) {
	target, err := s.ResolveTargetTenant(ctx, p, alertID)
	if err != nil {
		return uuid.Nil, "", err
	}
	if s.containment == nil {
		return uuid.Nil, "", httpx.ErrInternal("fleet containment path not configured")
	}
	// An incident is dedup/linkage metadata only (it is NOT the containment's action target — that is the
	// target's own playbook step, executed under the target's creds). Still, refuse a foreign incident so a
	// target-tenant run never references an incident from another tenant. Validated under the TARGET's RLS.
	if incidentID != nil {
		ok, err := s.incidentInTenant(ctx, target, *incidentID)
		if err != nil {
			return uuid.Nil, "", httpx.ErrInternal("could not validate incident")
		}
		if !ok {
			return uuid.Nil, "", httpx.ErrBadRequest("incident does not belong to the target tenant")
		}
	}
	return s.containment.RunForTarget(ctx, p, target, playbookID, incidentID)
}

// incidentInTenant reports whether the incident exists in the given tenant. The query runs under the tenant's
// RLS, so a foreign incident is invisible (returns false) — never an existence oracle across tenants.
func (s *Service) incidentInTenant(ctx context.Context, tenantID, incidentID uuid.UUID) (bool, error) {
	var exists bool
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM incidents WHERE id=$1)`, incidentID).Scan(&exists)
	})
	return exists, err
}

// RejectContainment rejects (cancels) a pending cross-tenant containment run the operator earlier fired.
// Same fleet gate as fire/approve (target re-resolved from the alert); rejection is fail-safe (nothing
// executes) so it needs no four-eyes — any authorized operator may cancel a stranded pending run.
func (s *Service) RejectContainment(ctx context.Context, p auth.Principal, alertID, runID uuid.UUID) (uuid.UUID, string, error) {
	target, err := s.ResolveTargetTenant(ctx, p, alertID)
	if err != nil {
		return uuid.Nil, "", err
	}
	if s.containment == nil {
		return uuid.Nil, "", httpx.ErrInternal("fleet containment path not configured")
	}
	return s.containment.RejectForTarget(ctx, p, target, runID)
}

// ApproveContainment approves a pending cross-tenant containment run an operator earlier fired (four-eyes:
// the operator who requested it may not approve it; the approver floor is measured in the TARGET tenant).
// The run's TARGET tenant is re-resolved from the alert at approval time (fire-time re-check), so the run can
// only be approved by an operator still in fleet scope for that resource.
func (s *Service) ApproveContainment(ctx context.Context, p auth.Principal, alertID, runID uuid.UUID) (uuid.UUID, string, error) {
	target, err := s.ResolveTargetTenant(ctx, p, alertID)
	if err != nil {
		return uuid.Nil, "", err
	}
	if s.containment == nil {
		return uuid.Nil, "", httpx.ErrInternal("fleet containment path not configured")
	}
	return s.containment.ApproveForTarget(ctx, p, target, runID)
}

// auditCallback builds the post-mutation callback that records a fleet write in the TARGET tenant's audit trail
// with the OPERATOR's real identity (#4 — data-owner-visibility on the write side: the agency sees who acted on
// its resource). It is handed to the alert service's *Tx methods, so it runs inside the MUTATION's transaction —
// which the alert repo has already opened under WithTenant(target). tenant_id comes from that GUC via the
// audit_log default, so the row lands in the target tenant. Because it shares the mutation's tx, a failure here
// rolls the mutation back (NFR-003): a cross-tenant write is NEVER applied without its attributing audit row.
func (s *Service) auditCallback(p auth.Principal, action string, alertID uuid.UUID, meta map[string]any) func(context.Context, pgx.Tx) error {
	return func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{
			ActorID:    p.UserID,
			ActorEmail: p.Email,
			Action:     action,
			Target:     "alert:" + alertID.String(),
			Metadata:   meta,
		})
	}
}
