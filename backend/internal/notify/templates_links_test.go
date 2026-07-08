package notify

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRenderString(t *testing.T) {
	out := renderString("A {{severity}} incident {{title}} ({{incident_id}})", map[string]string{
		"severity": "high", "title": "Ransomware", "incident_id": "INC-1",
	})
	if out != "A high incident Ransomware (INC-1)" {
		t.Fatalf("render wrong: %q", out)
	}
	// Missing var renders empty; unknown placeholder left blank.
	if got := renderString("hi {{missing}}!", map[string]string{}); got != "hi !" {
		t.Fatalf("missing var should render empty: %q", got)
	}
}

func TestSecureLink_SignVerifyRoundTrip(t *testing.T) {
	s := &Service{linkKey: []byte("test-link-key-0123456789")}
	tid := uuid.New()
	now := time.Unix(1_700_000_000, 0)
	token, err := s.GenerateLink(tid, "evidence-pack/INC-1", time.Hour, now)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	gotTid, res, err := s.VerifyLink(token, now.Add(30*time.Minute))
	if err != nil || gotTid != tid || res != "evidence-pack/INC-1" {
		t.Fatalf("verify within ttl failed: tid=%v res=%q err=%v", gotTid, res, err)
	}
	// Expired.
	if _, _, err := s.VerifyLink(token, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired link must fail")
	}
	// Tampered signature.
	if _, _, err := s.VerifyLink(token+"x", now.Add(time.Minute)); err == nil {
		t.Fatal("tampered token must fail")
	}
	// Tampered payload (flip a byte in the payload segment) must fail the HMAC.
	bad := "AAAA." + token[len(token)-43:]
	if _, _, err := s.VerifyLink(bad, now); err == nil {
		t.Fatal("forged payload must fail")
	}
}

func TestSecureLink_RequiresKey(t *testing.T) {
	s := &Service{}
	if _, err := s.GenerateLink(uuid.New(), "x", time.Hour, time.Unix(1, 0)); err == nil {
		t.Fatal("no link key configured must error")
	}
}
