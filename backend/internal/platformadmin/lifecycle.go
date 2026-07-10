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

// OffboardTenant purges all of a tenant's data via the uniform routine (blocked while on legal hold), marks the
// tenant deleted, and returns a certificate of destruction. Irreversible.
func (s *Service) OffboardTenant(ctx context.Context, actor auth.Principal, tenantID uuid.UUID, reason string) (string, error) {
	if strings.TrimSpace(reason) == "" {
		return "", httpx.ErrBadRequest("a reason is required to delete a tenant")
	}
	n, err := s.repo.OffboardPurge(ctx, tenantID) // the SECURITY DEFINER routine refuses if on legal hold
	if err != nil {
		if strings.Contains(err.Error(), "legal hold") {
			return "", httpx.ErrForbidden("tenant is on legal hold; clear the hold before deletion")
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
