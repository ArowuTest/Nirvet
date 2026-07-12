package reporting

// §6.13 #188 — the regulatory breach report's Ed25519 signature (non-repudiation for a regulator-lodged
// notification). Verifies: a signed payload validates against the in-band public key, a tampered field breaks
// verification, and with no signer wired the report is emitted unsigned (back-compat).

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
)

func sampleBreachIncident() BreachIncident {
	ack := time.Now().Add(-90 * time.Minute)
	closed := time.Now().Add(-10 * time.Minute)
	return BreachIncident{
		ID: uuid.New(), Title: "data exfil", Severity: "critical", Category: "exfiltration", Stage: "closed",
		CreatedAt: time.Now().Add(-2 * time.Hour), AcknowledgedAt: &ack, ClosedAt: &closed,
		Disposition: "true_positive", RootCause: "phished cred", Impact: "one mailbox",
		ActionsTaken: "isolated + reset", LessonsLearned: "enforce MFA", CustomerAck: true,
	}
}

// A signed breach payload verifies against the emitted public key; tampering any covered field breaks it.
func TestBreachSign_VerifyAndTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rs := &ReportService{signer: priv}
	inc := sampleBreachIncident()

	sg := rs.signBreach(inc)
	if sg.Sig == "" || sg.Pub == "" {
		t.Fatal("expected a signature + public key")
	}
	gotPub, _ := base64.StdEncoding.DecodeString(sg.Pub)
	if string(gotPub) != string(pub) {
		t.Fatal("emitted public key must match the signer")
	}
	sig, _ := base64.StdEncoding.DecodeString(sg.Sig)
	if !ed25519.Verify(pub, canonicalBreachPayload(inc), sig) {
		t.Fatal("signature must verify over the canonical payload")
	}
	// Tamper: change a covered field → the canonical payload differs → verification fails.
	tampered := inc
	tampered.Disposition = "false_positive"
	if ed25519.Verify(pub, canonicalBreachPayload(tampered), sig) {
		t.Fatal("a tampered breach payload must NOT verify against the original signature")
	}
}

// With no signer wired, the report is unsigned (empty signature) — back-compat, never a fake signature.
func TestBreachSign_UnsignedWhenNoSigner(t *testing.T) {
	rs := &ReportService{} // no signer
	sg := rs.signBreach(sampleBreachIncident())
	if sg.Sig != "" || sg.Pub != "" {
		t.Fatalf("no signer must yield an unsigned report, got %+v", sg)
	}
	// The dataset carries no signature meta when unsigned.
	ds := buildBreachReport(uuid.New(), sampleBreachIncident(), sg)
	if _, ok := ds.Meta["signature"]; ok {
		t.Fatal("unsigned report must not carry a signature meta field")
	}
}
