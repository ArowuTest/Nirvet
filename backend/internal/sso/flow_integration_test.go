package sso_test

// End-to-end OIDC login against a mock IdP (RSA-signed id_token, real discovery +
// JWKS + token endpoints), exercised through the real Service against a migrated
// Postgres. Gated on NIRVET_TEST_DATABASE_URL.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/iam"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/sso"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// mockIdP is a minimal OIDC provider: discovery, JWKS and token endpoints.
type mockIdP struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	idToken  string // returned by the token endpoint (set per-test after Start)
}

func newMockIdP(t *testing.T, clientID string) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	m := &mockIdP{key: key, clientID: clientID}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := m.srv.URL
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 base,
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"jwks_uri":               base + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256", "n": n, "e": e}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": m.idToken})
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

// signID mints an id_token for the given email + nonce (valid unless overridden).
func (m *mockIdP) signID(t *testing.T, email, nonce string, mutate func(jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": m.srv.URL, "aud": m.clientID, "sub": "idp|" + email,
		"email": email, "email_verified": true, "nonce": nonce,
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-key"
	s, err := tok.SignedString(m.key)
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	return s
}

func TestSSO_OIDCFlow(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run SSO integration tests")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "sso-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cipher, _ := crypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	tokens := auth.NewManager("sso-test-secret", "nirvet", 15*time.Minute)
	iamSvc := iam.NewService(iam.NewRepository(db), db, tokens, cipher)
	ssoSvc := sso.NewService(sso.NewRepository(db), sso.NewClient(), cipher, iamSvc, tokens, db, "state-secret")

	// Unique per-run domain: email_domain is globally unique among enabled
	// connections (a domain maps to one IdP), so tests must not reuse a fixed one.
	domain := "d" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12] + ".example.com"
	user := "sso-user@" + domain

	idp := newMockIdP(t, "client-123")
	conn, err := ssoSvc.CreateConnection(ctx, tn.ID, sso.CreateInput{
		Issuer: idp.srv.URL, ClientID: "client-123", ClientSecret: "shh",
		RedirectURI: "https://app.nirvet.local/sso/callback",
		DefaultRole: string(auth.RoleCustomerViewer), EmailDomain: domain,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}

	// start returns the auth URL; extract the state + nonce the service generated.
	startAndState := func() (state, nonce string) {
		authURL, err := ssoSvc.Start(ctx, conn.ID.String(), "")
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		u, _ := url.Parse(authURL)
		q := u.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "client-123" {
			t.Fatalf("auth URL missing PKCE/client_id: %s", authURL)
		}
		return q.Get("state"), q.Get("nonce")
	}

	t.Run("HappyPath_JITProvisionAndSession", func(t *testing.T) {
		state, nonce := startAndState()
		idp.idToken = idp.signID(t, user, nonce, nil)

		res, err := ssoSvc.Callback(ctx, "auth-code", state)
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		if !res.Created || res.Email != user || res.TenantID != tn.ID {
			t.Fatalf("unexpected result: %+v", res)
		}
		// The issued session token must verify to a principal in this tenant.
		p, err := tokens.Verify(res.Token)
		if err != nil || p.TenantID != tn.ID || p.Email != user {
			t.Fatalf("session token invalid: p=%+v err=%v", p, err)
		}
		// Second login for the same user must link (not create) the existing account.
		state2, nonce2 := startAndState()
		idp.idToken = idp.signID(t, user, nonce2, nil)
		res2, err := ssoSvc.Callback(ctx, "auth-code", state2)
		if err != nil || res2.Created {
			t.Fatalf("second login should link existing user: created=%v err=%v", res2.Created, err)
		}
	})

	t.Run("FailClosed_NonceMismatch", func(t *testing.T) {
		state, _ := startAndState()
		// Sign with a WRONG nonce → verification must reject (replay/CSRF guard).
		idp.idToken = idp.signID(t, user, "not-the-nonce", nil)
		if _, err := ssoSvc.Callback(ctx, "auth-code", state); err == nil {
			t.Fatal("callback must fail on nonce mismatch")
		}
	})

	t.Run("FailClosed_WrongAudience", func(t *testing.T) {
		state, nonce := startAndState()
		idp.idToken = idp.signID(t, user, nonce, func(c jwt.MapClaims) { c["aud"] = "someone-else" })
		if _, err := ssoSvc.Callback(ctx, "auth-code", state); err == nil {
			t.Fatal("callback must fail when id_token audience is not our client_id")
		}
	})

	t.Run("FailClosed_EmailDomainNotAllowed", func(t *testing.T) {
		state, nonce := startAndState()
		idp.idToken = idp.signID(t, "attacker@evil.com", nonce, nil)
		if _, err := ssoSvc.Callback(ctx, "auth-code", state); err == nil {
			t.Fatal("callback must reject an email outside the connection's allowed domain")
		}
	})

	t.Run("FailClosed_TamperedState", func(t *testing.T) {
		idp.idToken = idp.signID(t, user, "x", nil)
		if _, err := ssoSvc.Callback(ctx, "auth-code", "not-a-valid-signed-state"); err == nil {
			t.Fatal("callback must reject an unsigned/forged state")
		}
	})
}
