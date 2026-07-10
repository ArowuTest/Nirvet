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
	if err := s.alerts.Assign(ctx, target, alertID, assignee); err != nil {
		return err
	}
	return s.auditTarget(ctx, target, p, "fleet.alert.assign", alertID, map[string]any{"assignee": assignee.String()})
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
	if err := s.alerts.Disposition(ctx, target, alertID, disposition, reason, p.UserID); err != nil {
		return err
	}
	return s.auditTarget(ctx, target, p, "fleet.alert.disposition", alertID, map[string]any{"disposition": disposition})
}

// auditTarget records a fleet write in the TARGET tenant's audit trail with the OPERATOR's real identity
// (#4 — data-owner-visibility on the write side: the agency sees who acted on its resource). tenant_id comes
// from the WithTenant(target) GUC via the audit_log default, so the row lands in the target tenant. A failure
// here does not undo the (already-applied) mutation — but it is returned so the caller surfaces the audit gap
// rather than silently dropping it (NFR-003).
func (s *Service) auditTarget(ctx context.Context, target uuid.UUID, p auth.Principal, action string, alertID uuid.UUID, meta map[string]any) error {
	return s.db.WithTenant(ctx, target, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{
			ActorID:    p.UserID,
			ActorEmail: p.Email,
			Action:     action,
			Target:     "alert:" + alertID.String(),
			Metadata:   meta,
		})
	})
}
