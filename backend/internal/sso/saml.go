package sso

// SAML 2.0 SP-initiated SSO (SRS §6.2 IAM-001). SECURITY: XML signature/canonical-
// ization is NOT hand-rolled — it is delegated to the vetted russellhaering/gosaml2
// (+ goxmldsig, + mattermost/xml-roundtrip-validator for XML Signature Wrapping
// defense). Every control at the ACS fails closed. This surface is flagged for the
// pre-go-live expert security review (see build/ARCHITECTURE_GATES.md).

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAMLService orchestrates SP-initiated SAML login and connection management. It
// reuses the shared Directory (JIT provisioning) and session/audit tail (completeSSO).
type SAMLService struct {
	repo        *SAMLRepository
	dir         Directory
	tokens      *auth.Manager
	db          *database.DB
	stateSecret []byte
}

// NewSAMLService builds the SAML service. stateSecret signs the RelayState that
// binds the ACS response to the AuthnRequest we issued (replay/CSRF defense).
func NewSAMLService(repo *SAMLRepository, dir Directory, tokens *auth.Manager, db *database.DB, stateSecret string) *SAMLService {
	return &SAMLService{repo: repo, dir: dir, tokens: tokens, db: db, stateSecret: []byte(stateSecret)}
}

// CreateConnection validates and stores a tenant's SAML connection.
func (s *SAMLService) CreateConnection(ctx context.Context, tenantID uuid.UUID, in SAMLCreateInput) (*SAMLConnection, error) {
	if in.IDPEntityID == "" || in.IDPSSOURL == "" || in.IDPCertificate == "" || in.SPEntityID == "" || in.ACSURL == "" {
		return nil, httpx.ErrBadRequest("idp_entity_id, idp_sso_url, idp_certificate, sp_entity_id and acs_url are required")
	}
	if _, err := parseIDPCert(in.IDPCertificate); err != nil {
		return nil, httpx.ErrBadRequest("idp_certificate is not a valid PEM X.509 certificate")
	}
	if in.DefaultRole == "" {
		in.DefaultRole = string(auth.RoleCustomerViewer)
	}
	if !ValidSSORole(in.DefaultRole) {
		return nil, httpx.ErrBadRequest("default_role must be a customer role (customer_viewer or customer_admin)")
	}
	c := &SAMLConnection{
		ID: uuid.New(), TenantID: tenantID,
		IDPEntityID: strings.TrimSpace(in.IDPEntityID), IDPSSOURL: strings.TrimSpace(in.IDPSSOURL),
		IDPCertificate: strings.TrimSpace(in.IDPCertificate), SPEntityID: strings.TrimSpace(in.SPEntityID),
		ACSURL: strings.TrimSpace(in.ACSURL), EmailAttribute: strings.TrimSpace(in.EmailAttribute),
		DefaultRole: in.DefaultRole, EmailDomain: strings.ToLower(strings.TrimSpace(in.EmailDomain)), Enabled: true,
	}
	if err := s.repo.Create(ctx, c); err != nil {
		return nil, httpx.ErrInternal("could not save connection")
	}
	return c, nil
}

// ListConnections returns a tenant's SAML connections.
func (s *SAMLService) ListConnections(ctx context.Context, tenantID uuid.UUID) ([]SAMLConnection, error) {
	return s.repo.List(ctx, tenantID)
}

// DeleteConnection removes a SAML connection.
func (s *SAMLService) DeleteConnection(ctx context.Context, tenantID, id uuid.UUID) error {
	if err := s.repo.Delete(ctx, tenantID, id); err != nil {
		return httpx.ErrNotFound("connection not found")
	}
	return nil
}

// samlState is the signed RelayState: it binds the eventual ACS response to the
// AuthnRequest ID we generated, so an assertion for a different (or no) request is
// rejected.
type samlState struct {
	ConnID    string `json:"cid"`
	RequestID string `json:"rid"`
	jwt.RegisteredClaims
}

// Start begins SP-initiated SAML login and returns the IdP redirect URL. Exactly
// one of connectionID/emailDomain selects the connection.
func (s *SAMLService) Start(ctx context.Context, connectionID, emailDomain string) (string, error) {
	connID, err := s.resolveConnID(ctx, connectionID, emailDomain)
	if err != nil {
		return "", err
	}
	conn, err := s.repo.GetForCallback(ctx, connID)
	if err != nil {
		return "", httpx.ErrNotFound("connection not found")
	}
	sp, err := s.buildSP(conn)
	if err != nil {
		return "", httpx.ErrInternal("saml sp init failed")
	}
	doc, err := sp.BuildAuthRequestDocument()
	if err != nil {
		return "", httpx.ErrInternal("could not build authn request")
	}
	requestID := ""
	if doc.Root() != nil {
		requestID = doc.Root().SelectAttrValue("ID", "")
	}
	if requestID == "" {
		return "", httpx.ErrInternal("authn request missing id")
	}
	relayState, err := s.signState(conn.ID, requestID)
	if err != nil {
		return "", httpx.ErrInternal("state error")
	}
	url, err := sp.BuildAuthURLRedirect(relayState, doc)
	if err != nil {
		return "", httpx.ErrInternal("could not build redirect")
	}
	return url, nil
}

// ACS validates a signed SAML Response and, on success, issues a Nirvet session.
// Controls (all fail-closed): signature (vs IdP cert), time window, audience,
// recipient, issuer, InResponseTo binding, email-domain allowlist.
func (s *SAMLService) ACS(ctx context.Context, encodedResponse, relayState string) (*LoginResult, error) {
	if encodedResponse == "" || relayState == "" {
		return nil, httpx.ErrBadRequest("SAMLResponse and RelayState are required")
	}
	st, err := s.verifyState(relayState)
	if err != nil {
		return nil, httpx.ErrBadRequest("invalid or expired RelayState")
	}
	connID, err := uuid.Parse(st.ConnID)
	if err != nil {
		return nil, httpx.ErrBadRequest("invalid RelayState")
	}
	conn, err := s.repo.GetForCallback(ctx, connID)
	if err != nil {
		return nil, httpx.ErrNotFound("connection not found")
	}
	sp, err := s.buildSP(conn)
	if err != nil {
		return nil, httpx.ErrInternal("saml sp init failed")
	}

	// Signature validation (vs the connection's IdP cert) + condition checks. Errors
	// here mean an invalid/unsigned/tampered assertion — reject.
	info, err := sp.RetrieveAssertionInfo(encodedResponse)
	if err != nil {
		return nil, httpx.ErrUnauthorized("SAML assertion validation failed")
	}
	if info.WarningInfo == nil {
		return nil, httpx.ErrUnauthorized("SAML assertion could not be verified")
	}
	if info.WarningInfo.InvalidTime {
		return nil, httpx.ErrUnauthorized("SAML assertion outside its validity window")
	}
	if info.WarningInfo.NotInAudience {
		return nil, httpx.ErrUnauthorized("SAML assertion audience does not match this service provider")
	}

	// InResponseTo binding: the assertion must answer the request WE issued (defends
	// against replay, CSRF and IdP-initiated assertion injection).
	if !s.inResponseToMatches(info, st.RequestID) {
		return nil, httpx.ErrUnauthorized("SAML assertion does not correspond to this login request")
	}

	email := s.extractEmail(info, conn.EmailAttribute)
	if email == "" {
		return nil, httpx.ErrUnauthorized("SAML assertion has no email identifier")
	}
	if conn.EmailDomain != "" && !strings.HasSuffix(email, "@"+conn.EmailDomain) {
		return nil, httpx.ErrForbidden("email domain not permitted for this connection")
	}

	return completeSSO(ctx, s.dir, s.tokens, s.db, conn.TenantID, email, conn.DefaultRole,
		"auth.saml_login", "connection:"+conn.ID.String(), map[string]any{"idp": conn.IDPEntityID})
}

// inResponseToMatches checks the assertion's SubjectConfirmationData InResponseTo
// equals the AuthnRequest id we signed into RelayState. An empty/absent value fails.
func (s *SAMLService) inResponseToMatches(info *saml2.AssertionInfo, requestID string) bool {
	if requestID == "" || len(info.Assertions) == 0 {
		return false
	}
	subj := info.Assertions[0].Subject
	if subj == nil || subj.SubjectConfirmation == nil || subj.SubjectConfirmation.SubjectConfirmationData == nil {
		return false
	}
	return subj.SubjectConfirmation.SubjectConfirmationData.InResponseTo == requestID
}

// extractEmail returns the configured email attribute, or the NameID if none is set.
func (s *SAMLService) extractEmail(info *saml2.AssertionInfo, attr string) string {
	if attr != "" {
		if v := info.Values.Get(attr); v != "" {
			return strings.ToLower(strings.TrimSpace(v))
		}
		return ""
	}
	return strings.ToLower(strings.TrimSpace(info.NameID))
}

func (s *SAMLService) resolveConnID(ctx context.Context, connectionID, emailDomain string) (uuid.UUID, error) {
	switch {
	case connectionID != "":
		id, err := uuid.Parse(connectionID)
		if err != nil {
			return uuid.Nil, httpx.ErrBadRequest("invalid connection id")
		}
		return id, nil
	case emailDomain != "":
		id, err := s.repo.FindByDomain(ctx, strings.ToLower(emailDomain))
		if err != nil {
			return uuid.Nil, httpx.ErrNotFound("no SAML connection for that domain")
		}
		return id, nil
	default:
		return uuid.Nil, httpx.ErrBadRequest("connection or domain is required")
	}
}

// buildSP constructs the gosaml2 service provider for a connection. Signature
// validation is ON (SkipSignatureValidation defaults false); AuthnRequests are not
// signed (deferred — the critical direction is validating the IdP's signed response).
func (s *SAMLService) buildSP(conn *SAMLConnection) (*saml2.SAMLServiceProvider, error) {
	cert, err := parseIDPCert(conn.IDPCertificate)
	if err != nil {
		return nil, err
	}
	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      conn.IDPSSOURL,
		IdentityProviderIssuer:      conn.IDPEntityID,
		ServiceProviderIssuer:       conn.SPEntityID,
		AssertionConsumerServiceURL: conn.ACSURL,
		AudienceURI:                 conn.SPEntityID,
		IDPCertificateStore:         store,
		SignAuthnRequests:           false,
	}, nil
}

func parseIDPCert(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func (s *SAMLService) signState(connID uuid.UUID, requestID string) (string, error) {
	now := time.Now()
	c := samlState{
		ConnID: connID.String(), RequestID: requestID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "nirvet-saml",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(s.stateSecret)
}

func (s *SAMLService) verifyState(state string) (*samlState, error) {
	c := &samlState{}
	_, err := jwt.ParseWithClaims(state, c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.stateSecret, nil
	}, jwt.WithIssuer("nirvet-saml"), jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	return c, nil
}
