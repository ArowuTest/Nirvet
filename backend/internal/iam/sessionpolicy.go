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
			`SELECT tenant_id, access_ttl_seconds, ip_allowlist, geo_anomaly_logging
			   FROM session_policies WHERE tenant_id=$1`, tenantID).
			Scan(&p.TenantID, &p.AccessTTLSeconds, &p.IPAllowlist, &p.GeoAnomalyLogging)
	})
	if err != nil {
		return nil, err
	}
	if p.IPAllowlist == nil {
		p.IPAllowlist = []string{}
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

// SessionPolicyInput updates the policy (nil fields unchanged).
type SessionPolicyInput struct {
	AccessTTLSeconds  *int      `json:"access_ttl_seconds"`
	IPAllowlist       *[]string `json:"ip_allowlist"`
	GeoAnomalyLogging *bool     `json:"geo_anomaly_logging"`
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
	err = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			`UPDATE session_policies SET access_ttl_seconds=$2, ip_allowlist=$3, geo_anomaly_logging=$4, updated_at=now()
			   WHERE tenant_id=$1`, tenantID, cur.AccessTTLSeconds, cur.IPAllowlist, cur.GeoAnomalyLogging); e != nil {
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

// cachedPolicy returns the tenant's policy from the short-TTL cache, loading it on a miss.
func (s *Service) cachedPolicy(ctx context.Context, tenantID uuid.UUID) SessionPolicy {
	if v, ok := sessionPolicyCache.Load(tenantID); ok {
		if c := v.(cachedSessionPolicy); time.Now().Before(c.expires) {
			return c.pol
		}
	}
	p, err := s.GetSessionPolicy(ctx, tenantID)
	if err != nil || p == nil {
		return SessionPolicy{TenantID: tenantID} // fail-open on load error: empty allow-list = no restriction
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

// CheckSession enforces the tenant IP allow-list on a resolved Principal (implements
// auth.SessionChecker). An empty allow-list means no restriction. Access from outside the
// allow-list is denied and, when geo_anomaly_logging is on, recorded to the audit trail.
func (s *Service) CheckSession(ctx context.Context, p auth.Principal, clientIP string) error {
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
