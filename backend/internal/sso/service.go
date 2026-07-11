package sso

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Directory looks up and just-in-time provisions users for SSO. Implemented by
// iam.Service; kept narrow so sso does not depend on the iam package.
type Directory interface {
	// LookupForSSO finds a user by email across tenants (auth lookup). ok=false if none.
	LookupForSSO(ctx context.Context, email string) (id, tenantID uuid.UUID, role string, ok bool, err error)
	// ProvisionForSSO creates an SSO user in the tenant with the given role (no password login).
	ProvisionForSSO(ctx context.Context, tenantID uuid.UUID, email, role string) (id uuid.UUID, err error)
	// SessionTTL returns the tenant's configured access-token lifetime (0 => manager default),
	// so SSO logins honour the same §6.2 IAM-007 session policy as password logins.
	SessionTTL(ctx context.Context, tenantID uuid.UUID) time.Duration
	// MintSession issues a session token through iam's single stamp chokepoint (MA-SR-9), so an SSO login's token
	// carries the current session generation just like a password login. It stamps the passed principal (pointer)
	// with the gen/tgen the token carries. SSO must NOT mint tokens directly.
	MintSession(ctx context.Context, p *auth.Principal, ttl time.Duration) (string, error)
}

// Service orchestrates the OIDC login flow and connection management.
type Service struct {
	repo        *Repository
	oidc        *Client
	cipher      crypto.SecretCipher
	dir         Directory
	tokens      *auth.Manager
	db          *database.DB
	stateSecret []byte
}

// NewService builds the SSO service. stateSecret signs the short-lived OIDC state
// (carrying connection id, nonce and PKCE verifier) so the flow needs no server session.
func NewService(repo *Repository, oidc *Client, cipher crypto.SecretCipher, dir Directory, tokens *auth.Manager, db *database.DB, stateSecret string) *Service {
	return &Service{repo: repo, oidc: oidc, cipher: cipher, dir: dir, tokens: tokens, db: db, stateSecret: []byte(stateSecret)}
}

// CreateConnection validates and stores a tenant's OIDC connection (secret sealed).
func (s *Service) CreateConnection(ctx context.Context, tenantID uuid.UUID, in CreateInput) (*Connection, error) {
	if in.Issuer == "" || in.ClientID == "" || in.ClientSecret == "" || in.RedirectURI == "" {
		return nil, httpx.ErrBadRequest("issuer, client_id, client_secret and redirect_uri are required")
	}
	// H-NEW: validate the issuer at save time (absolute https + non-internal host). Discovery,
	// token exchange and JWKS all fetch from URLs derived from this tenant-controlled issuer; the
	// SafeClient guards the dial, this rejects an obvious internal/metadata issuer at the door.
	iu, perr := url.Parse(strings.TrimSpace(in.Issuer))
	if perr != nil || iu.Scheme != "https" || iu.Host == "" {
		return nil, httpx.ErrBadRequest("issuer must be an absolute https URL")
	}
	if netsafe.IsInternalHost(iu.Hostname()) {
		return nil, httpx.ErrBadRequest("issuer host is not permitted")
	}
	if in.DefaultRole == "" {
		in.DefaultRole = string(auth.RoleCustomerViewer)
	}
	if !ValidSSORole(in.DefaultRole) {
		return nil, httpx.ErrBadRequest("default_role must be a customer role (customer_viewer or customer_admin)")
	}
	sealed, err := s.cipher.Encrypt(tenantID, []byte(in.ClientSecret))
	if err != nil {
		return nil, httpx.ErrInternal("could not seal client secret")
	}
	c := &Connection{
		ID: uuid.New(), TenantID: tenantID, Protocol: "oidc",
		Issuer: strings.TrimSpace(in.Issuer), ClientID: in.ClientID, ClientSecret: sealed,
		RedirectURI: in.RedirectURI, DefaultRole: in.DefaultRole,
		EmailDomain: strings.ToLower(strings.TrimSpace(in.EmailDomain)), Enabled: true,
	}
	if err := s.repo.Create(ctx, c); err != nil {
		return nil, httpx.ErrInternal("could not save connection")
	}
	return c, nil
}

// ListConnections returns a tenant's connections.
func (s *Service) ListConnections(ctx context.Context, tenantID uuid.UUID) ([]Connection, error) {
	return s.repo.List(ctx, tenantID)
}

// DeleteConnection removes a connection.
func (s *Service) DeleteConnection(ctx context.Context, tenantID, id uuid.UUID) error {
	if err := s.repo.Delete(ctx, tenantID, id); err != nil {
		return httpx.ErrNotFound("connection not found")
	}
	return nil
}

// stateClaims is the signed, short-lived OIDC state.
type stateClaims struct {
	ConnID   string `json:"cid"`
	Nonce    string `json:"non"`
	Verifier string `json:"ver"`
	jwt.RegisteredClaims
}

// Start begins an OIDC login. Exactly one of connectionID/emailDomain identifies
// the IdP. It returns the authorization URL the browser should be sent to.
func (s *Service) Start(ctx context.Context, connectionID, emailDomain string) (string, error) {
	var connID uuid.UUID
	switch {
	case connectionID != "":
		id, err := uuid.Parse(connectionID)
		if err != nil {
			return "", httpx.ErrBadRequest("invalid connection id")
		}
		connID = id
	case emailDomain != "":
		id, err := s.repo.FindByDomain(ctx, strings.ToLower(emailDomain))
		if err != nil {
			return "", httpx.ErrNotFound("no SSO connection for that domain")
		}
		connID = id
	default:
		return "", httpx.ErrBadRequest("connection or domain is required")
	}

	conn, err := s.repo.GetForCallback(ctx, connID)
	if err != nil {
		return "", httpx.ErrNotFound("connection not found")
	}
	meta, err := s.oidc.Discover(ctx, conn.Issuer)
	if err != nil {
		return "", httpx.ErrBadGateway("IdP discovery failed")
	}
	nonce, err := Nonce()
	if err != nil {
		return "", httpx.ErrInternal("state error")
	}
	verifier, challenge, err := PKCE()
	if err != nil {
		return "", httpx.ErrInternal("pkce error")
	}
	state, err := s.signState(conn.ID, nonce, verifier)
	if err != nil {
		return "", httpx.ErrInternal("state error")
	}
	return AuthURL(meta, conn.ClientID, conn.RedirectURI, state, nonce, challenge), nil
}

// Callback completes the flow: verify state, exchange the code, verify the
// id_token, JIT-provision the user, and issue a Nirvet session token.
func (s *Service) Callback(ctx context.Context, code, state string) (*LoginResult, error) {
	if code == "" || state == "" {
		return nil, httpx.ErrBadRequest("code and state are required")
	}
	st, err := s.verifyState(state)
	if err != nil {
		return nil, httpx.ErrBadRequest("invalid or expired state")
	}
	connID, err := uuid.Parse(st.ConnID)
	if err != nil {
		return nil, httpx.ErrBadRequest("invalid state")
	}
	conn, err := s.repo.GetForCallback(ctx, connID)
	if err != nil {
		return nil, httpx.ErrNotFound("connection not found")
	}
	meta, err := s.oidc.Discover(ctx, conn.Issuer)
	if err != nil {
		return nil, httpx.ErrBadGateway("IdP discovery failed")
	}
	secret, err := s.cipher.Decrypt(conn.TenantID, conn.ClientSecret)
	if err != nil {
		return nil, httpx.ErrInternal("could not open client secret")
	}
	idToken, err := s.oidc.Exchange(ctx, meta, conn.ClientID, string(secret), conn.RedirectURI, code, st.Verifier)
	if err != nil {
		return nil, httpx.ErrUnauthorized("token exchange failed")
	}
	claims, err := s.oidc.VerifyIDToken(ctx, meta, conn.ClientID, idToken, st.Nonce)
	if err != nil {
		return nil, httpx.ErrUnauthorized("id_token verification failed")
	}
	// Fail-closed on the tenant's email-domain allowlist.
	if conn.EmailDomain != "" {
		if !strings.HasSuffix(claims.Email, "@"+conn.EmailDomain) {
			return nil, httpx.ErrForbidden("email domain not permitted for this connection")
		}
	}

	// JIT provisioning + session issue + audit (shared with SAML — one tested path).
	return completeSSO(ctx, s.dir, s.tokens, s.db, conn.TenantID, claims.Email, conn.DefaultRole,
		"auth.sso_login", "connection:"+conn.ID.String(), map[string]any{"issuer": conn.Issuer})
}

func (s *Service) signState(connID uuid.UUID, nonce, verifier string) (string, error) {
	now := time.Now()
	c := stateClaims{
		ConnID: connID.String(), Nonce: nonce, Verifier: verifier,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "nirvet-sso",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(s.stateSecret)
}

func (s *Service) verifyState(state string) (*stateClaims, error) {
	c := &stateClaims{}
	_, err := jwt.ParseWithClaims(state, c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.stateSecret, nil
	}, jwt.WithIssuer("nirvet-sso"), jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	return c, nil
}
