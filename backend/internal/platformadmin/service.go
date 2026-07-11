package platformadmin

// §6.18 #122 P-2 — the flag set/rollback service. This is where the safety classification becomes an authority gate:
//   immutable  → rejected at save (400) + the attempt audited (config can never set it).
//   protected + flip toward LESS-secure → senior role + four-eyes (distinct approver) + reason + a HIGH alert.
//   protected toward more-secure, or guarded → reason required.
//   open → applied, audited.
// Rollback re-runs the SAME gate (delegates to SetFlag with the prior value), so rolling a protected flag back into a
// less-secure state needs the same envelope; the result carries the security delta in plain terms.

import (
	"context"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Reinf-B: a protected flag weakening is always time-boxed so a forgotten loosening cannot persist. Default box if
// the admin does not specify; hard cap regardless.
const (
	defaultTimeBox = time.Hour
	maxTimeBox     = 24 * time.Hour
)

// Alerter raises the HIGH alert when a protected flag is weakened. *alert.Service satisfies it structurally.
type Alerter interface {
	RaisePlatform(ctx context.Context, tenantID uuid.UUID, dedupeKey, title, severity, targetRef, source string) (bool, error)
}

// SessionRevoker kills every live session in a tenant by bumping its session generation (§6.2 revocation).
// *iam.Service satisfies it. Used on offboard so a purged tenant's tokens are rejected immediately (the tombstone
// row survives the purge — mig 0093).
type SessionRevoker interface {
	BumpTenantGeneration(ctx context.Context, tenantID uuid.UUID) error
}

// Service owns the flag write path + its safety gate.
type Service struct {
	repo    *Repository
	alerter Alerter
	revoker SessionRevoker // optional; set via WithSessionRevoker
}

// NewService builds the service.
func NewService(repo *Repository, alerter Alerter) *Service {
	return &Service{repo: repo, alerter: alerter}
}

// WithSessionRevoker wires the session revoker so tenant offboarding also kills the tenant's live sessions.
func (s *Service) WithSessionRevoker(r SessionRevoker) *Service { s.revoker = r; return s }

// SetFlagInput is a flag mutation request. ApprovedBy is the four-eyes co-signer required to weaken a protected flag.
type SetFlagInput struct {
	Key        string
	Scope      string
	ScopeRef   string
	Enabled    bool
	Reason     string
	ApprovedBy *uuid.UUID
	ExpiresAt  *time.Time // Reinf-B: requested time-box for a protected weakening (capped; defaulted if nil)
}

// SetResult reports what happened, including the security delta (surfaced for rollback previews + audit legibility).
type SetResult struct {
	Applied       bool        `json:"applied"`
	Class         SafetyClass `json:"class"`
	LessSecure    bool        `json:"less_secure"`
	SecurityDelta string      `json:"security_delta"`
}

func isSenior(r auth.Role) bool { return r == auth.RolePlatformAdmin || r == auth.RoleSOCManager }

func boolStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// SetFlag validates against the safety class, applies + audits, and alerts on a weakening.
func (s *Service) SetFlag(ctx context.Context, actor auth.Principal, in SetFlagInput) (SetResult, error) {
	if in.Scope == "" {
		in.Scope = "global"
	}
	class := ClassOf(in.Key)
	ch := FlagChange{Key: in.Key, Scope: in.Scope, ScopeRef: in.ScopeRef, Enabled: in.Enabled,
		SafetyClass: string(class), ActorID: actor.UserID, Reason: in.Reason}

	if class == ClassImmutable {
		_ = s.repo.AuditRejected(ctx, ch, "immutable flag cannot be set via config")
		return SetResult{}, httpx.ErrBadRequest("immutable flag cannot be set via config: " + in.Key)
	}

	secure := SecureDefault(in.Key)
	lessSecure := class == ClassProtected && in.Enabled != secure

	switch {
	case lessSecure:
		if !isSenior(actor.Role) {
			return SetResult{}, httpx.ErrForbidden("weakening a protected flag requires a senior admin")
		}
		if in.ApprovedBy == nil || *in.ApprovedBy == actor.UserID {
			return SetResult{}, httpx.ErrForbidden("four-eyes: a distinct approver is required to weaken a protected flag")
		}
		if strings.TrimSpace(in.Reason) == "" {
			return SetResult{}, httpx.ErrBadRequest("a reason is required to weaken a protected flag")
		}
	case class == ClassGuarded || class == ClassProtected:
		if strings.TrimSpace(in.Reason) == "" {
			return SetResult{}, httpx.ErrBadRequest("a reason is required for a " + string(class) + " flag change")
		}
	}

	// Reinf-B: a protected weakening carries a bounded expiry (default 1h, cap 24h); a tightening/other change clears
	// any prior box. The auto-revert sweep reverts an expired weakening to its secure default.
	if lessSecure {
		until := time.Now().Add(defaultTimeBox)
		if in.ExpiresAt != nil {
			if capAt := time.Now().Add(maxTimeBox); in.ExpiresAt.After(capAt) {
				until = capAt
			} else if in.ExpiresAt.After(time.Now()) {
				until = *in.ExpiresAt
			}
		}
		ch.ExpiresAt = &until
	}

	old, err := s.repo.ApplyFlagChange(ctx, ch)
	if err != nil {
		return SetResult{}, err
	}

	oldStr := "unset"
	if old != nil {
		oldStr = boolStr(*old)
	}
	dir := "toward secure"
	if lessSecure {
		dir = "toward LESS-SECURE"
	}
	delta := in.Key + " " + oldStr + "→" + boolStr(in.Enabled) + " [" + string(class) + ", " + dir + "]"

	if lessSecure {
		title := "Feature flag WEAKENED: " + delta + " by " + actor.Email + " — reason: " + in.Reason
		_, _ = s.alerter.RaisePlatform(ctx, actor.TenantID,
			"flag-weakened:"+in.Key+":"+in.Scope+":"+in.ScopeRef, title, "high", "flag:"+in.Key, "platform-admin")
	}
	return SetResult{Applied: true, Class: class, LessSecure: lessSecure, SecurityDelta: delta}, nil
}

// RollbackFlag re-applies the value recorded in a prior flag-audit row as a NEW forward change — re-running the same
// safety gate (rolling a protected flag back into a less-secure state needs the same senior+four-eyes envelope).
func (s *Service) RollbackFlag(ctx context.Context, actor auth.Principal, auditID uuid.UUID, approvedBy *uuid.UUID) (SetResult, error) {
	row, found, err := s.repo.GetFlagAudit(ctx, auditID)
	if err != nil {
		return SetResult{}, err
	}
	if !found {
		return SetResult{}, httpx.ErrNotFound("config-audit row not found")
	}
	return s.SetFlag(ctx, actor, SetFlagInput{
		Key: row.Key, Scope: row.Scope, ScopeRef: row.ScopeRef, Enabled: row.Enabled,
		Reason: "rollback to audit " + auditID.String(), ApprovedBy: approvedBy,
	})
}
