package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
	"github.com/golang-jwt/jwt/v5"
)

// Metadata is the subset of OIDC provider metadata Nirvet needs (RFC 8414).
type Metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// IDClaims are the identity claims Nirvet consumes from a verified id_token.
type IDClaims struct {
	Subject       string
	Email         string
	EmailVerified bool
}

// Client performs the OIDC authorization-code flow. Discovery and HTTP are
// injectable so the flow is testable against a mock IdP and portable (ADR-0005).
type Client struct {
	http     *http.Client
	discover func(ctx context.Context, issuer string) (*Metadata, error)
}

// NewClient builds a client with real discovery over HTTPS. The HTTP client is a
// netsafe.SafeClient (H-NEW): discovery, token exchange and JWKS are all fetched from
// tenant-controlled URLs (issuer + the endpoints in its discovery doc), so the dial-time
// guard rejects internal/metadata IPs (SSRF / DNS-rebinding safe) on every outbound call.
func NewClient() *Client {
	c := &Client{http: netsafe.SafeClient(15 * time.Second)}
	c.discover = c.discoverHTTP
	return c
}

// Discover returns the provider metadata for an issuer.
func (c *Client) Discover(ctx context.Context, issuer string) (*Metadata, error) {
	return c.discover(ctx, issuer)
}

func (c *Client) discoverHTTP(ctx context.Context, issuer string) (*Metadata, error) {
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: status %d", resp.StatusCode)
	}
	var m Metadata
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	if m.AuthorizationEndpoint == "" || m.TokenEndpoint == "" || m.JWKSURI == "" {
		return nil, fmt.Errorf("oidc discovery: incomplete metadata")
	}
	return &m, nil
}

// PKCE returns a code_verifier and its S256 code_challenge (RFC 7636).
func PKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// Nonce returns a random nonce/state value.
func Nonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthURL builds the authorization-endpoint redirect URL (S256 PKCE + nonce).
func AuthURL(m *Metadata, clientID, redirectURI, state, nonce, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return m.AuthorizationEndpoint + "?" + q.Encode()
}

// Exchange swaps an authorization code for tokens and returns the raw id_token.
func (c *Client) Exchange(ctx context.Context, m *Metadata, clientID, clientSecret, redirectURI, code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		ErrDesc string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Error != "" {
		return "", fmt.Errorf("oidc token: %s %s", out.Error, out.ErrDesc)
	}
	if out.IDToken == "" {
		return "", fmt.Errorf("oidc token: no id_token in response")
	}
	return out.IDToken, nil
}

// VerifyIDToken validates the id_token signature (RS256 via the IdP JWKS) and
// its issuer, audience, expiry and nonce, then returns the identity claims.
// Fail-closed: any check that does not pass returns an error.
func (c *Client) VerifyIDToken(ctx context.Context, m *Metadata, clientID, idToken, wantNonce string) (*IDClaims, error) {
	keys, err := c.fetchJWKS(ctx, m.JWKSURI)
	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(idToken, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("oidc: no JWKS key for kid %q", kid)
		}
		return k, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(m.Issuer),
		jwt.WithAudience(clientID),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token invalid: %w", err)
	}
	if n, _ := claims["nonce"].(string); n != wantNonce {
		return nil, fmt.Errorf("oidc: nonce mismatch")
	}
	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	if sub == "" || email == "" {
		return nil, fmt.Errorf("oidc: id_token missing sub/email")
	}
	// R6: enforce email_verified. If the IdP ASSERTS the address is unverified we must not
	// JIT-provision on it (an attacker who controls an unverified-email IdP account would
	// otherwise land in the tenant on a squatted address). A missing claim means the IdP does
	// not assert verification either way — allowed, since the tenant's email-domain allowlist
	// is the binding control there. Some IdPs encode the claim as the string "true"/"false".
	ev, present := boolClaim(claims["email_verified"])
	if present && !ev {
		return nil, fmt.Errorf("oidc: email not verified at identity provider")
	}
	return &IDClaims{Subject: sub, Email: strings.ToLower(email), EmailVerified: ev}, nil
}

// boolClaim reads a JSON claim that may be a real bool or the string "true"/"false"
// (some IdPs stringify email_verified). Returns present=false when the claim is absent.
func boolClaim(v any) (val, present bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

func (c *Client) fetchJWKS(ctx context.Context, uri string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := rsaPublicKey(k.N, k.E)
		if err != nil {
			return nil, err
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("oidc: JWKS has no RSA keys")
	}
	return out, nil
}

func rsaPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(nB64, "="))
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(eB64, "="))
	if err != nil {
		return nil, err
	}
	// e is a big-endian unsigned integer, usually 65537 (AQAB). R6: guard the length —
	// an oversized exponent would make `copy(buf[8-len(eb):], ...)` index with a negative
	// bound and panic (a malformed/hostile JWKS should be a clean error, not a crash).
	if len(eb) == 0 || len(eb) > 8 {
		return nil, fmt.Errorf("oidc: unsupported RSA exponent size (%d bytes)", len(eb))
	}
	var e uint64
	buf := make([]byte, 8)
	copy(buf[8-len(eb):], eb)
	e = binary.BigEndian.Uint64(buf)
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e)}, nil
}
