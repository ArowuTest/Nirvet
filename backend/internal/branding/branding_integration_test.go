package branding_test

// White-label branding — instance-level singleton, safe-by-validation. Verifies the default read, a set+get
// roundtrip, and that injection-vector inputs (javascript:/data:/http/protocol-relative logo, non-hex color,
// CRLF email, over-long name) are rejected even though only padmin can set them (defense in depth).

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/branding"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
)

func svc(t *testing.T) *branding.Service {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return branding.NewService(db)
}

func TestBranding_DefaultAndRoundtrip(t *testing.T) {
	s := svc(t)
	ctx := context.Background()

	// The seeded singleton always exists.
	if _, err := s.Get(ctx); err != nil {
		t.Fatalf("default get: %v", err)
	}

	// Set valid values → Get reflects them.
	in := branding.Input{OperatorName: "Ghana CSA SOC", LogoURL: "https://cdn.example.gh/logo.png", PrimaryColor: "#0a7d34", SupportEmail: "soc@csa.gov.gh"}
	got, err := s.Set(ctx, in)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if got.OperatorName != in.OperatorName || got.LogoURL != in.LogoURL || got.PrimaryColor != in.PrimaryColor || got.SupportEmail != in.SupportEmail {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	// A site-relative logo path is allowed.
	if _, err := s.Set(ctx, branding.Input{OperatorName: "X", LogoURL: "/assets/logo.svg", PrimaryColor: "#fff000"}); err != nil {
		t.Fatalf("relative logo should be allowed: %v", err)
	}
}

func TestBranding_RejectsInjectionVectors(t *testing.T) {
	s := svc(t)
	ctx := context.Background()
	bad := []branding.Input{
		{OperatorName: "X", LogoURL: "javascript:alert(1)"},         // XSS scheme
		{OperatorName: "X", LogoURL: "data:text/html;base64,PHN"},   // data URI
		{OperatorName: "X", LogoURL: "http://insecure.example/l"},   // non-https absolute
		{OperatorName: "X", LogoURL: "//evil.example/logo.png"},     // protocol-relative
		{OperatorName: "X", PrimaryColor: "red; background:url(x)"}, // CSS injection, not hex
		{OperatorName: "X", PrimaryColor: "#zzzzzz"},                // non-hex
		{OperatorName: "X", SupportEmail: "a@b\r\nBcc: evil"},       // CRLF header injection
		{OperatorName: ""}, // required
	}
	for i, in := range bad {
		if _, err := s.Set(ctx, in); err == nil {
			t.Fatalf("case %d must be rejected: %+v", i, in)
		}
	}
}
