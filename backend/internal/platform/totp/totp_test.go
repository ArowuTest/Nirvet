package totp

import (
	"testing"
	"time"
)

func TestRFC6238Vector(t *testing.T) {
	// RFC 6238 SHA-1 test vector: ASCII key "12345678901234567890" at T=59s
	// yields 287082 (8 digits); the low 6 digits are 287082.
	secret := enc.EncodeToString([]byte("12345678901234567890"))
	got, err := Code(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if got != "287082" {
		t.Fatalf("RFC6238 vector: got %s, want 287082", got)
	}
}

func TestCodeValidateRoundTrip(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Now()
	code, err := Code(secret, now)
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if !Validate(secret, code, now) {
		t.Fatal("current code must validate")
	}
	if Validate(secret, "000000", now.Add(10*time.Minute)) {
		t.Fatal("a stale/wrong code must not validate")
	}
}

func TestValidateSkewWindow(t *testing.T) {
	secret, _ := GenerateSecret()
	now := time.Now()
	prev, _ := Code(secret, now.Add(-30*time.Second))
	// A code from the previous 30s step should still validate (±1 window).
	if !Validate(secret, prev, now) {
		t.Fatal("previous-step code should validate within the skew window")
	}
}

func TestURI(t *testing.T) {
	u := URI("ABC", "user@t", "Nirvet")
	if u[:10] != "otpauth://" {
		t.Fatalf("bad uri: %s", u)
	}
}
