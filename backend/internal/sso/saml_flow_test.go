package sso_test

// End-to-end SP-initiated SAML login against a mock IdP that SIGNS a real SAML
// Response (goxmldsig), exercised through the real SAMLService against a migrated
// Postgres. This is the security-critical test: it proves the signature and every
// condition are actually enforced. Gated on NIRVET_TEST_DATABASE_URL.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
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
	"github.com/beevik/etree"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	dsig "github.com/russellhaering/goxmldsig"
)

const samlStateSecret = "saml-test-secret"

// mockIdP holds a signing keypair + its PEM cert (configured as the connection's
// trusted IdP cert).
type samlMockIdP struct {
	key     *rsa.PrivateKey
	certDER []byte
	certPEM string
}

func newSAMLMockIdP(t *testing.T) *samlMockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return &samlMockIdP{key: key, certDER: der, certPEM: pemStr}
}

// respOpts controls the SAML Response the mock IdP emits, so tests can violate
// exactly one control at a time.
type respOpts struct {
	issuer, audience, recipient, inResponseTo, nameID string
	notBefore, notOnOrAfter                           time.Time
}

// signedResponse builds a SAML Response with those options and signs it with the
// IdP key (enveloped), returning the base64 the ACS expects.
func (m *samlMockIdP) signedResponse(t *testing.T, o respOpts) string {
	t.Helper()
	iso := func(tm time.Time) string { return tm.UTC().Format(time.RFC3339) }
	now := time.Now()
	xmlStr := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp_%s" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s">
<saml:Issuer>%s</saml:Issuer>
<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
<saml:Assertion ID="_assert_%s" Version="2.0" IssueInstant="%s">
<saml:Issuer>%s</saml:Issuer>
<saml:Subject>
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s" InResponseTo="%s"/>
</saml:SubjectConfirmation>
</saml:Subject>
<saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
<saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AuthnStatement AuthnInstant="%s" SessionIndex="_sess"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
<saml:AttributeStatement><saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
</saml:Assertion>
</samlp:Response>`,
		uuid.NewString(), iso(now), o.recipient, o.inResponseTo,
		o.issuer,
		uuid.NewString(), iso(now), o.issuer,
		o.nameID,
		iso(o.notOnOrAfter), o.recipient, o.inResponseTo,
		iso(o.notBefore), iso(o.notOnOrAfter), o.audience,
		iso(now), o.nameID)

	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlStr); err != nil {
		t.Fatalf("parse response xml: %v", err)
	}
	ks := dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{m.certDER}, PrivateKey: m.key})
	ctx := dsig.NewDefaultSigningContext(ks)
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatalf("sig method: %v", err)
	}
	signed, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	out.WriteSettings = etree.WriteSettings{CanonicalAttrVal: true, CanonicalEndTags: true, CanonicalText: true}
	s, err := out.WriteToString()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestSAML_Flow(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run SAML integration tests")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "saml-" + uuid.NewString()})
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cipher, _ := crypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	tokens := auth.NewManager("saml-test-jwt", "nirvet", 15*time.Minute)
	iamSvc := iam.NewService(iam.NewRepository(db), db, tokens, cipher)
	svc := sso.NewSAMLService(sso.NewSAMLRepository(db), iamSvc, tokens, db, samlStateSecret)

	idp := newSAMLMockIdP(t)
	const spEntityID = "https://nirvet.example/sp"
	const acsURL = "https://nirvet.example/auth/sso/saml/acs"
	const idpEntityID = "https://idp.example/entity"
	domain := "d" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12] + ".example.com"
	user := "saml-user@" + domain

	conn, err := svc.CreateConnection(ctx, tn.ID, sso.SAMLCreateInput{
		IDPEntityID: idpEntityID, IDPSSOURL: "https://idp.example/sso", IDPCertificate: idp.certPEM,
		SPEntityID: spEntityID, ACSURL: acsURL, DefaultRole: string(auth.RoleCustomerViewer), EmailDomain: domain,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}

	// Start returns the IdP redirect; extract RelayState and the request ID we bound.
	startAndRequestID := func() (relayState, requestID string) {
		redirect, err := svc.Start(ctx, conn.ID.String(), "")
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		u, _ := url.Parse(redirect)
		relayState = u.Query().Get("RelayState")
		if relayState == "" {
			t.Fatalf("no RelayState in redirect %q", redirect)
		}
		tok, _ := jwt.Parse(relayState, func(*jwt.Token) (any, error) { return []byte(samlStateSecret), nil })
		requestID, _ = tok.Claims.(jwt.MapClaims)["rid"].(string)
		if requestID == "" {
			t.Fatal("no request id in RelayState")
		}
		return relayState, requestID
	}

	valid := func(reqID string) respOpts {
		return respOpts{
			issuer: idpEntityID, audience: spEntityID, recipient: acsURL, inResponseTo: reqID,
			nameID: user, notBefore: time.Now().Add(-5 * time.Minute), notOnOrAfter: time.Now().Add(5 * time.Minute),
		}
	}

	t.Run("HappyPath", func(t *testing.T) {
		rs, reqID := startAndRequestID()
		res, err := svc.ACS(ctx, idp.signedResponse(t, valid(reqID)), rs)
		if err != nil {
			t.Fatalf("ACS: %v", err)
		}
		if !res.Created || res.Email != user || res.TenantID != tn.ID {
			t.Fatalf("unexpected result: %+v", res)
		}
		p, verr := tokens.Verify(res.Token)
		if verr != nil || p.TenantID != tn.ID || p.Email != user {
			t.Fatalf("session token invalid: p=%+v err=%v", p, verr)
		}
		// Second login links the existing user (not created).
		rs2, reqID2 := startAndRequestID()
		res2, err := svc.ACS(ctx, idp.signedResponse(t, valid(reqID2)), rs2)
		if err != nil || res2.Created {
			t.Fatalf("second login should link existing user: created=%v err=%v", res2.Created, err)
		}
	})

	t.Run("FailClosed_TamperedAssertion", func(t *testing.T) {
		rs, reqID := startAndRequestID()
		enc := idp.signedResponse(t, valid(reqID))
		// Tamper AFTER signing: flip the email inside the signed doc → digest mismatch.
		raw, _ := base64.StdEncoding.DecodeString(enc)
		tampered := strings.Replace(string(raw), user, "attacker@"+domain, 1)
		if _, err := svc.ACS(ctx, base64.StdEncoding.EncodeToString([]byte(tampered)), rs); err == nil {
			t.Fatal("tampered assertion must be rejected (signature invalid)")
		}
	})

	t.Run("FailClosed_WrongIdPCertificate", func(t *testing.T) {
		rs, reqID := startAndRequestID()
		other := newSAMLMockIdP(t) // signs with a key the connection does NOT trust
		if _, err := svc.ACS(ctx, other.signedResponse(t, valid(reqID)), rs); err == nil {
			t.Fatal("assertion signed by an untrusted key must be rejected")
		}
	})

	t.Run("FailClosed_Expired", func(t *testing.T) {
		rs, reqID := startAndRequestID()
		o := valid(reqID)
		o.notBefore = time.Now().Add(-2 * time.Hour)
		o.notOnOrAfter = time.Now().Add(-1 * time.Hour) // already expired
		if _, err := svc.ACS(ctx, idp.signedResponse(t, o), rs); err == nil {
			t.Fatal("expired assertion must be rejected")
		}
	})

	t.Run("FailClosed_WrongAudience", func(t *testing.T) {
		rs, reqID := startAndRequestID()
		o := valid(reqID)
		o.audience = "https://someone-else/sp"
		if _, err := svc.ACS(ctx, idp.signedResponse(t, o), rs); err == nil {
			t.Fatal("assertion for a different audience must be rejected")
		}
	})

	t.Run("FailClosed_WrongIssuer", func(t *testing.T) {
		rs, reqID := startAndRequestID()
		o := valid(reqID)
		o.issuer = "https://evil-idp/entity"
		if _, err := svc.ACS(ctx, idp.signedResponse(t, o), rs); err == nil {
			t.Fatal("assertion from an unexpected issuer must be rejected")
		}
	})

	t.Run("FailClosed_InResponseToMismatch", func(t *testing.T) {
		rs, _ := startAndRequestID()
		o := valid("_not-the-request-id") // valid signature, wrong InResponseTo
		if _, err := svc.ACS(ctx, idp.signedResponse(t, o), rs); err == nil {
			t.Fatal("assertion not bound to our request must be rejected (replay/CSRF)")
		}
	})

	t.Run("FailClosed_ForgedRelayState", func(t *testing.T) {
		reqID := "x"
		if _, err := svc.ACS(ctx, idp.signedResponse(t, valid(reqID)), "not-a-signed-relaystate"); err == nil {
			t.Fatal("forged RelayState must be rejected")
		}
	})
}
