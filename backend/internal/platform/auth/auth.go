// Package auth provides JWT issuance/verification, password hashing, the request
// Principal, and RBAC helpers. Tenant isolation starts here: the authenticated
// Principal carries the tenant, which flows into every DB transaction (ADR-0001).
package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
)

// DeriveKey derives a purpose-specific 32-byte key from the master signing secret via HKDF-SHA256, so a
// lower-assurance HMAC surface (secure links, SSO/SAML state) uses a key cryptographically SEPARATE from
// the auth-token signing key — a weakness or oracle in one surface cannot bear on the other. No extra
// secret to provision: the separation is by the HKDF `info` label, not a new env var (builder-pass L1).
func DeriveKey(secret, purpose string) []byte {
	r := hkdf.New(sha256.New, []byte(secret), nil, []byte("nirvet/"+purpose))
	out := make([]byte, 32)
	_, _ = io.ReadFull(r, out)
	return out
}

// Role is a platform role. Nirvet distinguishes provider-side SOC roles from
// customer-side roles; RBAC is enforced per handler.
type Role string

const (
	RolePlatformAdmin  Role = "platform_admin"
	RoleSOCManager     Role = "soc_manager"
	RoleAnalystT1      Role = "analyst_t1"
	RoleAnalystT2      Role = "analyst_t2"
	RoleAnalystT3      Role = "analyst_t3"
	RoleDetectionEng   Role = "detection_engineer"
	RoleCustomerAdmin  Role = "customer_admin"
	RoleCustomerViewer Role = "customer_viewer"
	// Oversight scope-resolver family (Ghana operator seam): bounded, read-only, metadata-only cross-tenant
	// oversight over a SUBSET of the fleet, scoped by a grant. NOT operator/provider roles.
	RoleOrgSubAdmin Role = "org_sub_admin" // gov cyber authority overseeing its organisation's tenants
	RolePayer       Role = "payer"         // anchor/central-buyer overseeing its billing account's tenants
)

// Principal is the authenticated actor for a request. ElevationID is set only on ELEVATED tokens
// (minted for an active PAM/break-glass grant); it carries the grant's id so a per-request checker
// can confirm the grant is still active and reject a revoked one immediately (Round-4 M6).
type Principal struct {
	UserID      uuid.UUID
	TenantID    uuid.UUID
	Role        Role
	Email       string
	ElevationID string // "" for ordinary tokens; the elevation id for elevated tokens
	// ServiceAccount marks a NON-HUMAN principal (authenticated via an API key, not a human login).
	// It can only be set by the API-key resolver — a JWT (human) login never sets it, and it is not a
	// JWT claim, so a human cannot forge it. Consumers that gate INTERACTIVE HUMAN access (e.g. the
	// billing-suspension AccessGate) exempt machine principals so telemetry/ingest keeps flowing.
	ServiceAccount bool
	// Gen/TGen carry the per-user and per-tenant SESSION GENERATION the token was minted at (§6.2 session
	// revocation). Stamped at mint from the current generation; the per-request CheckSession rejects a token
	// whose generation is behind current (a bump = immediate revocation). Absent/0 on tokens minted before the
	// feature (still valid until the first bump).
	Gen  int64
	TGen int64
	// MFAPending marks a RESTRICTED forced-enrollment grace session (S1 force-MFA): an in-scope user with no
	// active MFA factor is not locked out and not let in — this token can reach ONLY the MFA enroll/activate
	// endpoints (the route factories 403 it everywhere else), and MintSession is the ONE mint that issues it.
	// A full session never carries it. Not settable via API — only the login/SSO grace path sets it.
	MFAPending bool
}

// Claims is the JWT payload.
type Claims struct {
	TenantID    string `json:"tid"`
	Role        string `json:"role"`
	Email       string `json:"email"`
	ElevationID string `json:"eid,omitempty"`  // elevated tokens only (Round-4 M6)
	Gen         int64  `json:"gen,omitempty"`  // per-user session generation at mint (session revocation)
	TGen        int64  `json:"tgen,omitempty"` // per-tenant session generation at mint (tenant-wide kill)
	MFAPending  bool   `json:"mfap,omitempty"` // restricted forced-MFA-enrollment grace session (S1)
	jwt.RegisteredClaims
}

// ErrMFAEnrollmentRequired is returned by the session-mint chokepoint (iam.Service.MintSession) when an in-scope
// user has no active MFA factor (S1 force-MFA). It lives here in the leaf auth package so both the mint owner
// (iam) and the SSO login path (sso) can recognise it and respond by minting the restricted grace session, without
// an import cycle. It is NOT a login failure.
var ErrMFAEnrollmentRequired = errors.New("mfa enrollment required")

// Manager issues and verifies tokens.
type Manager struct {
	secret    []byte
	issuer    string
	accessTTL time.Duration
}

// NewManager builds a token manager.
func NewManager(secret, issuer string, accessTTL time.Duration) *Manager {
	return &Manager{secret: []byte(secret), issuer: issuer, accessTTL: accessTTL}
}

// Issue creates a signed access token using the manager's default TTL.
func (m *Manager) Issue(p Principal) (string, error) { return m.IssueWithTTL(p, m.accessTTL) }

// IssueWithTTL creates a signed access token with an explicit lifetime — used so login can
// honour the tenant's configured session TTL (§6.2 IAM-007). A non-positive ttl falls back
// to the manager default.
func (m *Manager) IssueWithTTL(p Principal, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = m.accessTTL
	}
	now := time.Now()
	claims := Claims{
		TenantID:    p.TenantID.String(),
		Role:        string(p.Role),
		Email:       p.Email,
		ElevationID: p.ElevationID,
		Gen:         p.Gen,
		TGen:        p.TGen,
		MFAPending:  p.MFAPending,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   p.UserID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
}

// Verify parses and validates a token, returning the Principal.
func (m *Manager) Verify(token string) (Principal, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	}, jwt.WithIssuer(m.issuer), jwt.WithExpirationRequired())
	if err != nil {
		return Principal{}, err
	}
	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return Principal{}, errors.New("invalid subject")
	}
	tid, err := uuid.Parse(claims.TenantID)
	if err != nil {
		return Principal{}, errors.New("invalid tenant")
	}
	return Principal{UserID: uid, TenantID: tid, Role: Role(claims.Role), Email: claims.Email,
		ElevationID: claims.ElevationID, Gen: claims.Gen, TGen: claims.TGen, MFAPending: claims.MFAPending}, nil
}

// HashPassword returns a bcrypt hash.
func HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(b), err
}

// ComparePassword reports whether plain matches the bcrypt hash.
func ComparePassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// --- request context ---

type ctxKey string

const principalKey ctxKey = "principal"

// WithPrincipal stores the principal in the context.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFrom returns the principal from the context, if authenticated.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey).(Principal)
	return p, ok
}
