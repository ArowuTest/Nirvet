package iam

// Session & access policy (SRS §6.2 IAM-007): per-tenant, admin-configurable session TTL,
// IP allow-list, and geo/anomaly logging. The TTL is consumed at login; the IP allow-list is
// enforced in the auth middleware (iam.Service satisfies auth.SessionChecker). Nothing is a
// code constant — the defaults are seeded DB rows.

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SessionPolicy is a tenant's session/access policy.
type SessionPolicy struct {
	TenantID          uuid.UUID `json:"tenant_id"`
	AccessTTLSeconds  int       `json:"access_ttl_seconds"`
	IPAllowlist       []string  `json:"ip_allowlist"`
	GeoAnomalyLogging bool      `json:"geo_anomaly_logging"`
	// S1 force-MFA (2a): a tenant admin may REQUIRE MFA for their tenant's roles. This ADDS to the operator
	// instance floor (override-only-tightens) — it can never drop a floor role. Enforcement is at MintSession.
	RequireMFA       bool     `json:"require_mfa"`
	MFARequiredRoles []string `json:"mfa_required_roles"`
}

// sessionPolicyCache caches policies per tenant with a short TTL so the auth middleware does
// not hit the DB on every request. Invalidated on update.
type cachedSessionPolicy struct {
	pol     SessionPolicy
	expires time.Time
}

var (
	sessionPolicyCache    sync.Map // map[uuid.UUID]cachedSessionPolicy
	sessionPolicyCacheTTL = 30 * time.Second
)

func (s *Service) getSessionPolicyRow(ctx context.Context, tenantID uuid.UUID) (*SessionPolicy, error) {
	var p SessionPolicy
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id, access_ttl_seconds, ip_allowlist, geo_anomaly_logging, require_mfa, mfa_required_roles
			   FROM session_policies WHERE tenant_id=$1`, tenantID).
			Scan(&p.TenantID, &p.AccessTTLSeconds, &p.IPAllowlist, &p.GeoAnomalyLogging, &p.RequireMFA, &p.MFARequiredRoles)
	})
	if err != nil {
		return nil, err
	}
	if p.IPAllowlist == nil {
		p.IPAllowlist = []string{}
	}
	if p.MFARequiredRoles == nil {
		p.MFARequiredRoles = []string{}
	}
	return &p, nil
}

// GetSessionPolicy returns the tenant's policy, lazily seeding a default row if none exists
// (so the response is always the configurable default, never empty).
func (s *Service) GetSessionPolicy(ctx context.Context, tenantID uuid.UUID) (*SessionPolicy, error) {
	p, err := s.getSessionPolicyRow(ctx, tenantID)
	if err == pgx.ErrNoRows {
		_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO session_policies (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING`, tenantID)
			return e
		})
		p, err = s.getSessionPolicyRow(ctx, tenantID)
	}
	if err != nil {
		return nil, httpx.ErrInternal("could not load session policy")
	}
	return p, nil
}

// validMFARoleSet is every valid platform role — a tenant's mfa_required_roles entries are checked against it so a
// typo can't create a rule that matches no principal (silent under-enforcement). Includes the oversight roles.
var validMFARoleSet = map[auth.Role]bool{
	auth.RolePlatformAdmin: true, auth.RoleSOCManager: true, auth.RoleAnalystT1: true, auth.RoleAnalystT2: true,
	auth.RoleAnalystT3: true, auth.RoleDetectionEng: true, auth.RoleCustomerAdmin: true, auth.RoleCustomerViewer: true,
	auth.RoleOrgSubAdmin: true, auth.RolePayer: true,
}

// SessionPolicyInput updates the policy (nil fields unchanged).
type SessionPolicyInput struct {
	AccessTTLSeconds  *int      `json:"access_ttl_seconds"`
	IPAllowlist       *[]string `json:"ip_allowlist"`
	GeoAnomalyLogging *bool     `json:"geo_anomaly_logging"`
	RequireMFA        *bool     `json:"require_mfa"`        // S1 force-MFA (2a)
	MFARequiredRoles  *[]string `json:"mfa_required_roles"` // roles this tenant additionally requires MFA for
}

// UpdateSessionPolicy applies a partial update, validating the TTL bound and every allow-list
// entry (a bad CIDR/IP is rejected at write time, never silently ignored at enforce time).
func (s *Service) UpdateSessionPolicy(ctx context.Context, p auth.Principal, tenantID uuid.UUID, in SessionPolicyInput) (*SessionPolicy, error) {
	cur, err := s.GetSessionPolicy(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if in.AccessTTLSeconds != nil {
		if *in.AccessTTLSeconds < 60 || *in.AccessTTLSeconds > 86400 {
			return nil, httpx.ErrBadRequest("access_ttl_seconds must be between 60 and 86400")
		}
		cur.AccessTTLSeconds = *in.AccessTTLSeconds
	}
	if in.IPAllowlist != nil {
		for _, e := range *in.IPAllowlist {
			if !validIPEntry(e) {
				return nil, httpx.ErrBadRequest("invalid ip_allowlist entry: " + e)
			}
		}
		cur.IPAllowlist = *in.IPAllowlist
	}
	if in.GeoAnomalyLogging != nil {
		cur.GeoAnomalyLogging = *in.GeoAnomalyLogging
	}
	if in.RequireMFA != nil {
		cur.RequireMFA = *in.RequireMFA
	}
	if in.MFARequiredRoles != nil {
		// Reject unknown role strings so a typo can't silently create a rule that protects no one. The tenant
		// list only ADDS to the operator floor (union at enforce time) — it can never weaken it.
		for _, r := range *in.MFARequiredRoles {
			if !validMFARoleSet[auth.Role(r)] {
				return nil, httpx.ErrBadRequest("unknown role in mfa_required_roles: " + r)
			}
		}
		cur.MFARequiredRoles = *in.MFARequiredRoles
	}
	err = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			`UPDATE session_policies SET access_ttl_seconds=$2, ip_allowlist=$3, geo_anomaly_logging=$4,
			        require_mfa=$5, mfa_required_roles=$6, updated_at=now()
			   WHERE tenant_id=$1`, tenantID, cur.AccessTTLSeconds, cur.IPAllowlist, cur.GeoAnomalyLogging,
			cur.RequireMFA, cur.MFARequiredRoles); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "iam.session_policy_update", Target: "tenant:" + tenantID.String()})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not update session policy")
	}
	sessionPolicyCache.Delete(tenantID)
	return cur, nil
}

// cachedPolicy returns the tenant's policy from the short-TTL cache, loading it on a miss. On a load
// error it serves the LAST-KNOWN-GOOD value (stale-while-error, Round-4 M7) so a transient DB blip
// cannot silently drop a tenant's configured IP allow-list — the error-path collapse to an open
// policy was the fail-open bug. Only when the tenant has never been cached (cold cache + load error)
// does it fall back to the open default, since we then genuinely cannot know whether a list exists.
func (s *Service) cachedPolicy(ctx context.Context, tenantID uuid.UUID) SessionPolicy {
	cached, hasCached := sessionPolicyCache.Load(tenantID)
	if hasCached {
		if c := cached.(cachedSessionPolicy); time.Now().Before(c.expires) {
			return c.pol
		}
	}
	p, err := s.GetSessionPolicy(ctx, tenantID)
	if err != nil || p == nil {
		if hasCached {
			return cached.(cachedSessionPolicy).pol // stale-while-error: keep enforcing the known policy
		}
		return SessionPolicy{TenantID: tenantID}
	}
	sessionPolicyCache.Store(tenantID, cachedSessionPolicy{pol: *p, expires: time.Now().Add(sessionPolicyCacheTTL)})
	return *p
}

// SessionTTL is the exported form of sessionTTL — the SSO login tail resolves the tenant's
// configured token lifetime through this (implements sso.Directory.SessionTTL), so SSO and
// password logins honour the same §6.2 IAM-007 session policy.
func (s *Service) SessionTTL(ctx context.Context, tenantID uuid.UUID) time.Duration {
	return s.sessionTTL(ctx, tenantID)
}

// sessionTTL returns the tenant's configured access-token lifetime (0 => manager default).
func (s *Service) sessionTTL(ctx context.Context, tenantID uuid.UUID) time.Duration {
	p := s.cachedPolicy(ctx, tenantID)
	if p.AccessTTLSeconds <= 0 {
		return 0
	}
	return time.Duration(p.AccessTTLSeconds) * time.Second
}

// CheckSession is the per-request principal-validity hook (implements auth.SessionChecker). It (1)
// re-checks an elevated token's grant is still active (Round-4 M6 — immediate revocation), and (2)
// enforces the tenant IP allow-list (§6.2 IAM-007). An empty allow-list means no restriction; access
// from outside it is denied and, when geo_anomaly_logging is on, recorded to the audit trail.
func (s *Service) CheckSession(ctx context.Context, p auth.Principal, clientIP string) error {
	// Session revocation (§6.2): a token whose per-user/per-tenant generation is behind current is REVOKED
	// (password change/reset, offboard, admin-disable) — reject immediately rather than honour it until exp.
	// This is the first gate: a revoked session shouldn't pass the elevation/IP checks either.
	if err := s.checkSessionGeneration(ctx, p); err != nil {
		return err
	}
	// Revocable elevated tokens: a token minted for a PAM/break-glass grant carries the grant id; if
	// that grant is no longer active (revoked/expired/foreign), reject NOW rather than honouring the
	// elevated role until the token's ≤8h exp.
	if p.ElevationID != "" {
		if err := s.checkElevationActive(ctx, p); err != nil {
			return err
		}
	}
	pol := s.cachedPolicy(ctx, p.TenantID)
	if len(pol.IPAllowlist) == 0 {
		return nil
	}
	if ipAllowed(clientIP, pol.IPAllowlist) {
		return nil
	}
	if pol.GeoAnomalyLogging {
		_ = s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
			return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
				Action: "iam.session_ip_denied", Target: "user:" + p.UserID.String(),
				Metadata: map[string]any{"client_ip": clientIP}})
		})
	}
	return httpx.ErrForbidden("access from a network outside the tenant allow-list")
}

// --- IP helpers ---

func validIPEntry(e string) bool {
	e = strings.TrimSpace(e)
	if e == "" {
		return false
	}
	if strings.Contains(e, "/") {
		_, _, err := net.ParseCIDR(e)
		return err == nil
	}
	return net.ParseIP(e) != nil
}

func ipAllowed(clientIP string, allow []string) bool {
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	if ip == nil {
		return false // unparseable client IP fails closed against a non-empty allow-list
	}
	for _, e := range allow {
		e = strings.TrimSpace(e)
		if strings.Contains(e, "/") {
			if _, netw, err := net.ParseCIDR(e); err == nil && netw.Contains(ip) {
				return true
			}
			continue
		}
		if p := net.ParseIP(e); p != nil && p.Equal(ip) {
			return true
		}
	}
	return false
}
