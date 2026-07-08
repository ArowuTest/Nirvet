package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
)

func newTestCipher(t *testing.T) SecretCipher {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	c, err := NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	return c
}

// TestRoundTrip verifies a secret encrypts and decrypts for the same tenant.
func TestRoundTrip(t *testing.T) {
	c := newTestCipher(t)
	tenant := uuid.New()
	plaintext := []byte("oauth-refresh-token-abc123")

	ct, err := c.Encrypt(tenant, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(ct) == string(plaintext) {
		t.Fatal("ciphertext must not equal plaintext")
	}
	got, err := c.Decrypt(tenant, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q", got)
	}
}

// TestTenantIsolation is the ADR-0004 guarantee: a ciphertext sealed for tenant A
// cannot be opened under tenant B (tenant_id is the AES-GCM AAD).
func TestTenantIsolation(t *testing.T) {
	c := newTestCipher(t)
	tenantA, tenantB := uuid.New(), uuid.New()

	ct, err := c.Encrypt(tenantA, []byte("A-secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := c.Decrypt(tenantB, ct); err == nil {
		t.Fatal("SECURITY: tenant B must NOT be able to decrypt tenant A's ciphertext")
	}
}

// TestTampering verifies GCM rejects modified ciphertext.
func TestTampering(t *testing.T) {
	c := newTestCipher(t)
	tenant := uuid.New()
	ct, _ := c.Encrypt(tenant, []byte("data"))
	ct[len(ct)-1] ^= 0xFF // flip a bit in the tag/ciphertext
	if _, err := c.Decrypt(tenant, ct); err == nil {
		t.Fatal("SECURITY: tampered ciphertext must fail authentication")
	}
}

// TestDecryptLegacyFormat: a ciphertext written in the pre-version-byte layout
// [nonce][ciphertext] must still decrypt after the version byte was introduced, so a
// deploy does not orphan existing stored secrets (R2 M-NEW back-compat).
func TestDecryptLegacyFormat(t *testing.T) {
	c := newTestCipher(t)
	lc := c.(*localCipher)
	tenant := uuid.New()
	// Hand-build a LEGACY blob: [nonce][sealed], no version prefix.
	nonce := make([]byte, lc.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	sealed := lc.aead.Seal(nil, nonce, []byte("legacy-refresh-token"), tenant[:])
	legacy := append(append([]byte{}, nonce...), sealed...)

	got, err := c.Decrypt(tenant, legacy)
	if err != nil {
		t.Fatalf("legacy-format blob must still decrypt: %v", err)
	}
	if string(got) != "legacy-refresh-token" {
		t.Fatalf("legacy round-trip mismatch: got %q", got)
	}

	// And a current-format blob still round-trips.
	cur, _ := c.Encrypt(tenant, []byte("new-token"))
	if out, err := c.Decrypt(tenant, cur); err != nil || string(out) != "new-token" {
		t.Fatalf("current-format round-trip failed: out=%q err=%v", out, err)
	}
}

// TestNonceUniqueness verifies two encryptions of the same plaintext differ.
func TestNonceUniqueness(t *testing.T) {
	c := newTestCipher(t)
	tenant := uuid.New()
	a, _ := c.Encrypt(tenant, []byte("same"))
	b, _ := c.Encrypt(tenant, []byte("same"))
	if string(a) == string(b) {
		t.Fatal("ciphertexts of identical plaintext must differ (random nonce)")
	}
}
