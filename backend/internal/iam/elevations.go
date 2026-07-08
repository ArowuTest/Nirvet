package iam

// Privileged access management + break-glass (SRS §6.2 IAM-004/006). Time-bounded, justified,
// four-eyes-approved (or emergency) role elevation. Enforcement is stateless (AssumeRole): an
// active elevation lets its owner mint a short-lived elevated token; the record is the
// governance/audit/expiry layer.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	minElevationSeconds = 300   // 5 minutes
	maxElevationSeconds = 28800 // 8 hours
)

// knownRoles are the roles an elevation may target (platform_admin is intentionally absent —
// it is never grantable via elevation).
var knownRoles = map[auth.Role]bool{
	auth.RoleSOCManager: true, auth.RoleAnalystT1: true, auth.RoleAnalystT2: true,
	auth.RoleAnalystT3: true, auth.RoleDetectionEng: true,
	auth.RoleCustomerAdmin: true, auth.RoleCustomerViewer: true,
}

// Elevation is a privileged-access grant.
type Elevation struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	UserID          uuid.UUID  `json:"user_id"`
	UserEmail       string     `json:"user_email"`
	BaseRole        auth.Role  `json:"base_role"`
	ElevatedRole    auth.Role  `json:"elevated_role"`
	Kind            string     `json:"kind"`
	Reason          string     `json:"reason"`
	DurationSeconds int        `json:"duration_seconds"`
	Status          string     `json:"status"`
	ApproverEmail   string     `json:"approver_email"`
	GrantedAt       *time.Time `json:"granted_at,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	ReviewRequired  bool       `json:"review_required"`
	ReviewedBy      string     `json:"reviewed_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// effectiveStatus reports "expired" for an active grant past its window (derived at read time).
func (e *Elevation) effectiveStatus(now time.Time) string {
	if e.Status == "active" && e.ExpiresAt != nil && e.ExpiresAt.Before(now) {
		return "expired"
	}
	return e.Status
}

// validateTarget enforces the elevation boundary: a known role, never platform_admin, and the
// SAME domain as the base role (provider↔provider, customer↔customer) so a customer user can
// never cross into a SOC role.
func validateTarget(base, elevated auth.Role) error {
	if elevated == auth.RolePlatformAdmin || !knownRoles[elevated] {
		return httpx.ErrBadRequest("elevated_role must be a non-admin, grantable role")
	}
	if auth.IsProviderRole(base) != auth.IsProviderRole(elevated) {
		return httpx.ErrBadRequest("elevation may not cross the provider/customer boundary")
	}
	return nil
}

func clampDuration(d int) int {
	if d <= 0 {
		d = 3600
	}
	if d < minElevationSeconds {
		d = minElevationSeconds
	}
	if d > maxElevationSeconds {
		d = maxElevationSeconds
	}
	return d
}

// ElevationInput requests (or break-glasses) an elevation.
type ElevationInput struct {
	ElevatedRole    auth.Role `json:"elevated_role"`
	Reason          string    `json:"reason"`
	DurationSeconds int       `json:"duration_seconds"`
}

// RequestElevation creates a PAM elevation awaiting four-eyes approval (§6.2 IAM-004).
func (s *Service) RequestElevation(ctx context.Context, p auth.Principal, in ElevationInput) (*Elevation, error) {
	if strings.TrimSpace(in.Reason) == "" {
		return nil, httpx.ErrBadRequest("a justification reason is required")
	}
	if err := validateTarget(p.Role, in.ElevatedRole); err != nil {
		return nil, err
	}
	e := &Elevation{ID: uuid.New(), TenantID: p.TenantID, UserID: p.UserID, UserEmail: p.Email,
		BaseRole: p.Role, ElevatedRole: in.ElevatedRole, Kind: "pam", Reason: in.Reason,
		DurationSeconds: clampDuration(in.DurationSeconds), Status: "requested"}
	if err := s.insertElevation(ctx, p, e, "iam.elevation_request"); err != nil {
		return nil, err
	}
	return e, nil
}

// BreakGlass creates an IMMEDIATELY active emergency elevation (§6.2 IAM-006): no prior
// approval, but a mandatory reason, an automatic alert, and a required post-use review.
func (s *Service) BreakGlass(ctx context.Context, p auth.Principal, in ElevationInput) (*Elevation, error) {
	if strings.TrimSpace(in.Reason) == "" {
		return nil, httpx.ErrBadRequest("an emergency reason is required")
	}
	if err := validateTarget(p.Role, in.ElevatedRole); err != nil {
		return nil, err
	}
	now := time.Now()
	exp := now.Add(time.Duration(clampDuration(in.DurationSeconds)) * time.Second)
	e := &Elevation{ID: uuid.New(), TenantID: p.TenantID, UserID: p.UserID, UserEmail: p.Email,
		BaseRole: p.Role, ElevatedRole: in.ElevatedRole, Kind: "break_glass", Reason: in.Reason,
		DurationSeconds: clampDuration(in.DurationSeconds), Status: "active",
		GrantedAt: &now, ExpiresAt: &exp, ReviewRequired: true}
	if err := s.insertElevation(ctx, p, e, "iam.break_glass"); err != nil {
		return nil, err
	}
	// Automatic alert (IAM-006). Best-effort: the record + audit are the durable trail.
	if s.alerter != nil {
		_ = s.alerter.NotifyIncident(ctx, p.TenantID, "BREAK-GLASS access invoked",
			fmt.Sprintf("%s self-elevated to %s (emergency). Reason: %s. Post-use review required.",
				p.Email, in.ElevatedRole, in.Reason))
	}
	return e, nil
}

func (s *Service) insertElevation(ctx context.Context, p auth.Principal, e *Elevation, action string) error {
	err := s.db.WithTenant(ctx, e.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO privileged_elevations
			   (id, tenant_id, user_id, user_email, base_role, elevated_role, kind, reason,
			    duration_seconds, status, granted_at, expires_at, review_required)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			e.ID, e.TenantID, e.UserID, e.UserEmail, e.BaseRole, e.ElevatedRole, e.Kind, e.Reason,
			e.DurationSeconds, e.Status, e.GrantedAt, e.ExpiresAt, e.ReviewRequired); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: action,
			Target:   "elevation:" + e.ID.String(),
			Metadata: map[string]any{"elevated_role": e.ElevatedRole, "kind": e.Kind, "reason": e.Reason}})
	})
	if err != nil {
		return httpx.ErrInternal("could not create elevation")
	}
	return nil
}

// ApproveElevation grants a pending PAM request. Four-eyes: the approver must differ from the
// requester (route RBAC already restricts approvers to senior roles).
func (s *Service) ApproveElevation(ctx context.Context, approver auth.Principal, tenantID, id uuid.UUID) (*Elevation, error) {
	e, err := s.getElevation(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if e.Kind != "pam" || e.Status != "requested" {
		return nil, httpx.ErrConflict("elevation is not awaiting approval")
	}
	if e.UserID == approver.UserID {
		return nil, httpx.ErrForbidden("four-eyes: the requester cannot approve their own elevation")
	}
	now := time.Now()
	exp := now.Add(time.Duration(e.DurationSeconds) * time.Second)
	err = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE privileged_elevations SET status='active', approver_id=$2, approver_email=$3,
			   granted_at=$4, expires_at=$5 WHERE id=$1 AND status='requested'`,
			id, approver.UserID, approver.Email, now, exp); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: approver.UserID, ActorEmail: approver.Email,
			Action: "iam.elevation_approve", Target: "elevation:" + id.String(),
			Metadata: map[string]any{"user": e.UserEmail, "elevated_role": e.ElevatedRole}})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not approve elevation")
	}
	e.Status, e.ApproverEmail, e.GrantedAt, e.ExpiresAt = "active", approver.Email, &now, &exp
	return e, nil
}

// RejectElevation declines a pending PAM request.
func (s *Service) RejectElevation(ctx context.Context, approver auth.Principal, tenantID, id uuid.UUID, reason string) error {
	return s.setStatus(ctx, approver, tenantID, id, "rejected", "iam.elevation_reject",
		func(e *Elevation) error {
			if e.Status != "requested" {
				return httpx.ErrConflict("elevation is not awaiting approval")
			}
			return nil
		}, map[string]any{"reason": reason})
}

// RevokeElevation ends an active/requested elevation early.
func (s *Service) RevokeElevation(ctx context.Context, p auth.Principal, tenantID, id uuid.UUID) error {
	return s.setStatus(ctx, p, tenantID, id, "revoked", "iam.elevation_revoke",
		func(e *Elevation) error {
			if e.Status != "active" && e.Status != "requested" {
				return httpx.ErrConflict("elevation is not active")
			}
			return nil
		}, nil)
}

// ReviewElevation records the mandatory post-use review of a break-glass grant (IAM-006).
func (s *Service) ReviewElevation(ctx context.Context, reviewer auth.Principal, tenantID, id uuid.UUID, notes string) error {
	e, err := s.getElevation(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if !e.ReviewRequired {
		return httpx.ErrConflict("elevation does not require review")
	}
	err = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE privileged_elevations SET review_required=false, reviewed_at=now(), reviewed_by=$2 WHERE id=$1`,
			id, reviewer.Email); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: reviewer.UserID, ActorEmail: reviewer.Email,
			Action: "iam.elevation_review", Target: "elevation:" + id.String(),
			Metadata: map[string]any{"notes": notes, "user": e.UserEmail}})
	})
	if err != nil {
		return httpx.ErrInternal("could not record review")
	}
	return nil
}

// MintElevatedToken issues a short-lived elevated token for an ACTIVE elevation owned by the
// caller. TTL = min(remaining elevation window, tenant session TTL) — never longer than the
// grant. An expired/revoked/rejected or foreign elevation mints nothing (base role stands).
func (s *Service) MintElevatedToken(ctx context.Context, p auth.Principal, id uuid.UUID) (string, *Elevation, error) {
	e, err := s.getElevation(ctx, p.TenantID, id)
	if err != nil {
		return "", nil, err
	}
	if e.UserID != p.UserID {
		return "", nil, httpx.ErrForbidden("not your elevation")
	}
	now := time.Now()
	if e.effectiveStatus(now) != "active" || e.ExpiresAt == nil {
		return "", nil, httpx.ErrConflict("elevation is not active")
	}
	remaining := time.Until(*e.ExpiresAt)
	if remaining <= 0 {
		return "", nil, httpx.ErrConflict("elevation window has ended")
	}
	if sess := s.sessionTTL(ctx, p.TenantID); sess > 0 && sess < remaining {
		remaining = sess
	}
	elevated := auth.Principal{UserID: p.UserID, TenantID: p.TenantID, Role: e.ElevatedRole, Email: p.Email}
	token, terr := s.tokens.IssueWithTTL(elevated, remaining)
	if terr != nil {
		return "", nil, httpx.ErrInternal("could not issue elevated token")
	}
	_ = s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "iam.elevation_token", Target: "elevation:" + id.String(),
			Metadata: map[string]any{"elevated_role": e.ElevatedRole}})
	})
	return token, e, nil
}

// --- read helpers + generic status setter ---

const elevCols = `id, tenant_id, user_id, user_email, base_role, elevated_role, kind, reason,
	duration_seconds, status, approver_email, granted_at, expires_at, review_required, reviewed_by, created_at`

func scanElevation(row pgx.Row, e *Elevation) error {
	return row.Scan(&e.ID, &e.TenantID, &e.UserID, &e.UserEmail, &e.BaseRole, &e.ElevatedRole,
		&e.Kind, &e.Reason, &e.DurationSeconds, &e.Status, &e.ApproverEmail, &e.GrantedAt,
		&e.ExpiresAt, &e.ReviewRequired, &e.ReviewedBy, &e.CreatedAt)
}

func (s *Service) getElevation(ctx context.Context, tenantID, id uuid.UUID) (*Elevation, error) {
	var e Elevation
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return scanElevation(tx.QueryRow(ctx, `SELECT `+elevCols+` FROM privileged_elevations WHERE id=$1`, id), &e)
	})
	if err == pgx.ErrNoRows {
		return nil, httpx.ErrNotFound("elevation not found")
	}
	if err != nil {
		return nil, httpx.ErrInternal("could not load elevation")
	}
	return &e, nil
}

func (s *Service) setStatus(ctx context.Context, actor auth.Principal, tenantID, id uuid.UUID, status, action string, guard func(*Elevation) error, meta map[string]any) error {
	e, err := s.getElevation(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if guard != nil {
		if gerr := guard(e); gerr != nil {
			return gerr
		}
	}
	err = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE privileged_elevations SET status=$2 WHERE id=$1`, id, status); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: actor.UserID, ActorEmail: actor.Email,
			Action: action, Target: "elevation:" + id.String(), Metadata: meta})
	})
	if err != nil {
		return httpx.ErrInternal("could not update elevation")
	}
	return nil
}

// ListElevations returns the tenant's elevations (newest first), with derived expiry applied.
func (s *Service) ListElevations(ctx context.Context, tenantID uuid.UUID) ([]Elevation, error) {
	return s.queryElevations(ctx, tenantID, `SELECT `+elevCols+` FROM privileged_elevations ORDER BY created_at DESC LIMIT 500`)
}

// ListMyElevations returns the caller's own elevations.
func (s *Service) ListMyElevations(ctx context.Context, p auth.Principal) ([]Elevation, error) {
	return s.queryElevations(ctx, p.TenantID, `SELECT `+elevCols+` FROM privileged_elevations WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200`, p.UserID)
}

func (s *Service) queryElevations(ctx context.Context, tenantID uuid.UUID, q string, args ...any) ([]Elevation, error) {
	now := time.Now()
	var out []Elevation
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e Elevation
			if err := scanElevation(rows, &e); err != nil {
				return err
			}
			e.Status = e.effectiveStatus(now)
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}
