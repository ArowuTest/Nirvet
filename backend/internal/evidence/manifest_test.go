package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/google/uuid"
)

func signedPack(t *testing.T) (*Pack, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	svc := &Service{signer: priv}
	p := &Pack{
		SchemaVersion: PackSchemaVersion,
		GeneratedAt:   time.Unix(1_700_000_000, 0).UTC(),
		GeneratedBy:   "analyst@t",
		TenantID:      uuid.New(),
		Incident:      &incident.Incident{ID: uuid.New(), Title: "case", Severity: "high"},
		Alerts:        []alert.Alert{{ID: uuid.New(), Title: "a1", Severity: "high"}},
	}
	p.Manifest = svc.buildManifest(p)
	return p, pub
}

// TestManifestSignAndVerify: a freshly built pack verifies against the signer's public
// key; the manifest carries a real Ed25519 signature (R2 H-B).
func TestManifestSignAndVerify(t *testing.T) {
	p, pub := signedPack(t)
	if p.Manifest.Signature == nil || p.Manifest.Signature.Algorithm != "ed25519" {
		t.Fatal("manifest must carry an ed25519 signature")
	}
	if p.Manifest.PackDigest == "" {
		t.Fatal("pack digest must be set")
	}
	if err := Verify(p, pub); err != nil {
		t.Fatalf("a freshly signed pack must verify: %v", err)
	}
}

// TestVerifyDetectsSectionTamper: editing any section content after signing fails
// verification — the signature is no longer cosmetic.
func TestVerifyDetectsSectionTamper(t *testing.T) {
	p, pub := signedPack(t)
	p.Incident.Title = "tampered" // edit a section WITHOUT recomputing the manifest
	if err := Verify(p, pub); err == nil {
		t.Fatal("editing a section must fail verification")
	}
}

// TestVerifyDetectsEnvelopeTamper: editing the envelope metadata (which is now folded
// into the signed digest) fails verification — the R2 gap where the envelope was
// unhashed is closed.
func TestVerifyDetectsEnvelopeTamper(t *testing.T) {
	p, pub := signedPack(t)
	p.GeneratedBy = "attacker@evil" // envelope change, sections untouched
	if err := Verify(p, pub); err == nil {
		t.Fatal("editing the envelope metadata must fail verification")
	}
}

// TestVerifyRejectsForgedKey: re-signing a tampered pack with a DIFFERENT key must not
// pass verification against the trusted key (the embedded public key is not trusted).
func TestVerifyRejectsForgedKey(t *testing.T) {
	p, trusted := signedPack(t)
	// Attacker edits a section, recomputes the manifest with THEIR key, and swaps the
	// embedded public key to their own.
	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	p.Incident.Title = "benign now"
	p.Manifest = (&Service{signer: evil}).buildManifest(p)
	if err := Verify(p, trusted); err == nil {
		t.Fatal("a pack re-signed with an untrusted key must fail against the trusted key")
	}
}
