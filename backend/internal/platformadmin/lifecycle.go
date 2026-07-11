package platformadmin

// §6.18 #122 P-3 — tenant lifecycle + uniform offboarding (ADMIN-005 / TEN-009). legal_hold is an evidence-
// preservation control: setting it is routine padmin; CLEARING it (M-3) removes that control, so it carries the same
// elevated envelope as weakening a protected flag (senior + four-eyes + reason + HIGH alert). Deletion runs the
// uniform purge (blocked while on hold) and issues a certificate of destruction.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// requireElevated enforces the shared elevated envelope (senior + four-eyes + reason) used by protected-flag
// weakening and legal-hold clearing.
func requireElevated(actor auth.Principal, approvedBy *uuid.UUID, reason string) error {
	if !isSenior(actor.Role) {
		return httpx.ErrForbidden("this action requires a senior admin")
	}
	if approvedBy == nil || *approvedBy == actor.UserID {
		return httpx.ErrForbidden("four-eyes: a distinct approver is required")
	}
	if strings.TrimSpace(reason) == "" {
		return httpx.ErrBadRequest("a reason is required")
	}
	return nil
}

// SetLegalHold places a tenant on legal hold (padmin + reason). Blocks deletion until cleared.
func (s *Service) SetLegalHold(ctx context.Context, actor auth.Principal, tenantID uuid.UUID, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return httpx.ErrBadRequest("a reason is required to set legal hold")
	}
	return s.repo.SetLegalHold(ctx, tenantID, true, actor.UserID, reason, "legal_hold_set")
}

// ClearLegalHold lifts a hold — M-3: removes an evidence-preservation control, so it needs the elevated envelope
// (senior + four-eyes + reason) and raises a HIGH alert.
func (s *Service) ClearLegalHold(ctx context.Context, actor auth.Principal, tenantID uuid.UUID, reason string, approvedBy *uuid.UUID) error {
	if err := requireElevated(actor, approvedBy, reason); err != nil {
		return err
	}
	if err := s.repo.SetLegalHold(ctx, tenantID, false, actor.UserID, reason, "legal_hold_clear"); err != nil {
		return err
	}
	_, _ = s.alerter.RaisePlatform(ctx, tenantID, "legal-hold-cleared:"+tenantID.String(),
		"Legal hold CLEARED for tenant "+tenantID.String()+" by "+actor.Email+" — reason: "+reason,
		"high", "tenant:"+tenantID.String(), "platform-admin")
	return nil
}

// MarkExported transitions a tenant to the 'exported' state (its data has been exported to the customer) and starts
// the retention clock. This is a required precondition of OffboardTenant — a tenant can only be purged from
// 'exported', after its retention window elapses. Routine padmin + reason (it destroys nothing; the destructive step
// is OffboardTenant, which carries the elevated envelope).
func (s *Service) MarkExported(ctx context.Context, actor auth.Principal, tenantID uuid.UUID, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return httpx.ErrBadRequest("a reason is required to mark a tenant exported")
	}
	return s.repo.MarkExported(ctx, tenantID, actor.UserID, reason)
}

// OffboardTenant purges all of a tenant's data via the uniform routine and returns a certificate of destruction.
// IRREVERSIBLE and strictly more destructive than clearing a legal hold, so it carries the SAME elevated envelope
// (senior + four-eyes + reason + HIGH alert) — H-1: it must never be gated weaker than the lesser action that merely
// enables it. The purge is additionally refused (defense in depth, inside the SECURITY DEFINER function) unless the
// tenant is on no legal hold, is in the 'exported' state, and its retention window has elapsed.
func (s *Service) OffboardTenant(ctx context.Context, actor auth.Principal, tenantID uuid.UUID, reason string, approvedBy *uuid.UUID) (string, error) {
	if err := requireElevated(actor, approvedBy, reason); err != nil {
		return "", err
	}
	// Kill every live session in the tenant BEFORE the purge (§6.2 revocation): bump the tenant generation so all
	// pre-offboard tokens are rejected immediately. The tombstone row survives the purge (mig 0093 excludes the
	// generation tables), so revoked stays revoked even after the tenant's data is gone.
	if s.revoker != nil {
		if err := s.revoker.BumpTenantGeneration(ctx, tenantID); err != nil {
			return "", httpx.ErrInternal("could not revoke tenant sessions before offboarding")
		}
	}
	n, err := s.repo.OffboardPurge(ctx, tenantID) // the SECURITY DEFINER routine refuses on hold / wrong-state / retention
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "legal hold"):
			return "", httpx.ErrForbidden("tenant is on legal hold; clear the hold before deletion")
		case strings.Contains(err.Error(), "exported state"):
			return "", httpx.ErrConflict("tenant is not in the exported state; export its data before deletion")
		case strings.Contains(err.Error(), "retention window"):
			return "", httpx.ErrConflict("tenant retention window has not elapsed; deletion is not yet permitted")
		}
		return "", err
	}
	cert := certOfDestruction(tenantID, n, actor.UserID)
	if err := s.repo.RecordDeletion(ctx, tenantID, n, cert, actor.UserID, reason); err != nil {
		return "", err
	}
	_, _ = s.alerter.RaisePlatform(ctx, tenantID, "tenant-deleted:"+tenantID.String(),
		fmt.Sprintf("Tenant %s OFFBOARDED (purged %d tables) by %s", tenantID, n, actor.Email),
		"high", "tenant:"+tenantID.String(), "platform-admin")
	return cert, nil
}

func certOfDestruction(tenantID uuid.UUID, tables int, actor uuid.UUID) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("destroy:%s:%d:%s", tenantID, tables, actor)))
	return hex.EncodeToString(h[:])
}
