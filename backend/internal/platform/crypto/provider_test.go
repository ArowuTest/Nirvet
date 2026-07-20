package crypto

// KMS provider abstraction — gate §4 falsification tests (increment 1: Vault + shared machinery). Each is
// mutation-sensitive: dropping the guard it targets turns it RED.
//
//	#1 round-trip per provider (+ wrong-tenant AAD fails)   — TestConformance_AllProviders, TestVaultTransit_REST
//	#2 KEK-never-leaves (wrap/unwrap only; no key export)   — fence check-kms-provider-boundary.sh + interface shape
//	#3 fail-closed provider-down (Encrypt+Decrypt error)    — TestEnvelope_FailClosed_NoLocalFallback (kms_test.go)
//	#4 provider-confusion refused (wrong tag/gen)           — TestEnvelope_ProviderConfusionRefused
//	#5 per-tenant isolation per provider                    — TestVaultTransit_PerTenantIsolation
//	#6 dual-read migration (no orphaned vault)              — TestTransition_CrossProviderDualRead
//	#7 require-KMS refuses localCipher                      — TestNewFromConfig_RequireKMS
//	#8 DEK zeroize preserved on every provider path         — TestEnvelope_DEKZeroized

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func readJSON(r *http.Request, out any) error { return json.NewDecoder(r.Body).Decode(out) }
func writeJSON(w http.ResponseWriter, v any)  { _ = json.NewEncoder(w).Encode(v) }

// ── Vault Transit loopback server ────────────────────────────────────────────────────────────────────────────
// Emulates transit encrypt/decrypt with a reversible transform that EMBEDS the key name + aad into the ciphertext,
// so decrypt can verify BOTH (proves per-tenant key separation and aad binding, not just a blind round-trip).

const vaultTestToken = "s.testtoken"

func vaultTestServer(t *testing.T) *vaultTransit {
	t.Helper()
	xor := func(b []byte) []byte {
		out := make([]byte, len(b))
		for i, x := range b {
			out[i] = x ^ 0x3C
		}
		return out
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != vaultTestToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var in map[string]string
		_ = readJSON(r, &in)
		switch {
		case strings.Contains(r.URL.Path, "/transit/encrypt/"):
			key := strings.TrimPrefix(r.URL.Path, "/v1/transit/encrypt/")
			pt, _ := base64.StdEncoding.DecodeString(in["plaintext"])
			aad, _ := base64.StdEncoding.DecodeString(in["associated_data"])
			// ciphertext embeds key\x00aad\x00xor(pt) so decrypt can verify the key+aad match.
			var blob []byte
			blob = append(blob, key...)
			blob = append(blob, 0)
			blob = append(blob, aad...)
			blob = append(blob, 0)
			blob = append(blob, xor(pt)...)
			ct := "vault:v1:" + base64.StdEncoding.EncodeToString(blob)
			writeJSON(w, map[string]any{"data": map[string]string{"ciphertext": ct}})
		case strings.Contains(r.URL.Path, "/transit/decrypt/"):
			key := strings.TrimPrefix(r.URL.Path, "/v1/transit/decrypt/")
			aad, _ := base64.StdEncoding.DecodeString(in["associated_data"])
			raw := strings.TrimPrefix(in["ciphertext"], "vault:v1:")
			blob, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			i1 := bytes.IndexByte(blob, 0)
			rest := blob[i1+1:]
			i2 := bytes.IndexByte(rest, 0)
			gotKey := string(blob[:i1])
			gotAAD := rest[:i2]
			body := rest[i2+1:]
			if gotKey != key || !bytes.Equal(gotAAD, aad) {
				// key or aad mismatch → Vault refuses (this is the per-tenant + aad-binding guard).
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]any{"data": map[string]string{"plaintext": base64.StdEncoding.EncodeToString(xor(body))}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	v := newVaultTransit(srv.URL, "transit", func(context.Context) (string, error) { return vaultTestToken, nil })
	v.http = srv.Client() // loopback isn't SafeClient-blocked (and vault uses a plain client anyway)
	return v
}

// #1 (vault): the REST wrapper round-trips a DEK, binds the tenant AAD, and checks the token.
func TestVaultTransit_REST(t *testing.T) {
	v := vaultTestServer(t)
	dek := bytes.Repeat([]byte{0xA5}, 32)
	aad := []byte("tenant-aad")
	wrapped, err := v.Wrap(context.Background(), "tenant-key", dek, aad)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if !strings.HasPrefix(string(wrapped), "vault:v1:") {
		t.Fatalf("vault wrapped bytes should be the opaque vault:v1: token, got %q", wrapped)
	}
	got, err := v.Unwrap(context.Background(), "tenant-key", wrapped, aad)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap round-trip: got %x err %v", got, err)
	}
	// Wrong AAD at unwrap → refused (aad binding on the KEK op).
	if _, err := v.Unwrap(context.Background(), "tenant-key", wrapped, []byte("other")); err == nil {
		t.Fatal("unwrap with wrong aad must fail")
	}
	// A bad token → the wrapper surfaces the error (fail loud).
	v.token = func(context.Context) (string, error) { return "wrong", nil }
	if _, err := v.Wrap(context.Background(), "k", dek, aad); err == nil {
		t.Fatal("a wrong vault token must surface as an error")
	}
}

// #5: a DEK wrapped under tenant A's transit key cannot be unwrapped under tenant B's key (per-tenant separation
// holds for Vault as it does for GCP).
func TestVaultTransit_PerTenantIsolation(t *testing.T) {
	v := vaultTestServer(t)
	dek := bytes.Repeat([]byte{7}, 32)
	aad := []byte("aad")
	wrappedA, err := v.Wrap(context.Background(), "tenant-A-key", dek, aad)
	if err != nil {
		t.Fatalf("wrap A: %v", err)
	}
	if _, err := v.Unwrap(context.Background(), "tenant-B-key", wrappedA, aad); err == nil {
		t.Fatal("tenant B's key must NOT unwrap tenant A's wrapped DEK (per-tenant separation)")
	}
	if _, err := v.Unwrap(context.Background(), "tenant-A-key", wrappedA, aad); err != nil {
		t.Fatalf("tenant A's own key must unwrap: %v", err)
	}
}

// #1 (§3 conformance): the SAME vectors run against EACH real provider (gcp REST + vault REST). A new provider can't
// ship without passing wrap→unwrap→identity + tenant-AAD binding.
func TestConformance_AllProviders(t *testing.T) {
	providers := map[string]keyWrapper{
		"gcp":   gcpTestServer(t),
		"vault": vaultTestServer(t),
	}
	for name, w := range providers {
		t.Run(name, func(t *testing.T) {
			dek := bytes.Repeat([]byte{0x11}, 32)
			aad := []byte("tenant-xyz")
			wrapped, err := w.Wrap(context.Background(), "conf-key", dek, aad)
			if err != nil {
				t.Fatalf("%s wrap: %v", name, err)
			}
			got, err := w.Unwrap(context.Background(), "conf-key", wrapped, aad)
			if err != nil || !bytes.Equal(got, dek) {
				t.Fatalf("%s round-trip: got %x err %v", name, got, err)
			}
			// tenant-AAD binding: a different aad must NOT unwrap.
			if _, err := w.Unwrap(context.Background(), "conf-key", wrapped, []byte("different")); err == nil {
				t.Fatalf("%s: unwrap with a different aad must fail (tenant binding)", name)
			}
		})
	}
}

// gcpTestServer builds a gcpKMS against a loopback KMS emulator (same shape as kms_test's, exposed for conformance).
func gcpTestServer(t *testing.T) *gcpKMS {
	t.Helper()
	xor := func(b []byte) []byte {
		out := make([]byte, len(b))
		for i, x := range b {
			out[i] = x ^ 0x5A
		}
		return out
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var in map[string]string
		_ = readJSON(r, &in)
		switch {
		case strings.HasSuffix(r.URL.Path, ":encrypt"):
			pt, _ := base64.StdEncoding.DecodeString(in["plaintext"])
			// embed aad so a mismatched aad at :decrypt fails (tenant binding on the KEK op).
			aad, _ := base64.StdEncoding.DecodeString(in["additionalAuthenticatedData"])
			var blob []byte
			blob = append(blob, aad...)
			blob = append(blob, 0)
			blob = append(blob, xor(pt)...)
			writeJSON(w, map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(blob)})
		case strings.HasSuffix(r.URL.Path, ":decrypt"):
			ct, _ := base64.StdEncoding.DecodeString(in["ciphertext"])
			aad, _ := base64.StdEncoding.DecodeString(in["additionalAuthenticatedData"])
			i := bytes.IndexByte(ct, 0)
			if i < 0 || !bytes.Equal(ct[:i], aad) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]string{"plaintext": base64.StdEncoding.EncodeToString(xor(ct[i+1:]))})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return &gcpKMS{endpoint: srv.URL, token: func(context.Context) (string, error) { return "test-token", nil }, http: srv.Client()}
}

// #4: a ciphertext tagged provider-A (or gen-N) fed to provider-B (or gen-M) is REFUSED — never silently mis-unwrapped.
// Mutation: drop the tag/gen check in envelopeCipher.Decrypt → these go RED.
func TestEnvelope_ProviderConfusionRefused(t *testing.T) {
	vaultEnv := newEnvelopeCipher(&fakeWrapper{}, tmpl, tagVault, 1)
	gcpEnv := newEnvelopeCipher(&fakeWrapper{}, tmpl, tagGCP, 1)
	tid := uuid.New()
	ctVault, err := vaultEnv.Encrypt(tid, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ctVault[1] != byte(tagVault) {
		t.Fatalf("v2 blob must carry the provider tag at byte 1, got %d", ctVault[1])
	}
	// A vault-tagged blob handed to the gcp cipher must refuse (provider confusion).
	if _, err := gcpEnv.Decrypt(tid, ctVault); err == nil {
		t.Fatal("provider-confusion: a vault-tagged ciphertext must NOT unwrap under the gcp cipher")
	}
	// Same provider, different key-generation → also refused.
	gen2 := newEnvelopeCipher(&fakeWrapper{}, tmpl, tagVault, 2)
	if _, err := gen2.Decrypt(tid, ctVault); err == nil {
		t.Fatal("key-gen mismatch: a gen-1 blob must NOT unwrap under a gen-2 cipher")
	}
	// The matching provider+gen still decrypts (sanity: the refusal isn't blanket).
	if got, err := vaultEnv.Decrypt(tid, ctVault); err != nil || string(got) != "secret" {
		t.Fatalf("matching provider must decrypt: got %q err %v", got, err)
	}
}

// #6: after switching provider via transitionCipher, OLD-provider ciphertext still decrypts (write-new/read-both) —
// no data orphaned. Mutation: a single-reader (writer only) after the switch → the old vault blob is unreadable → RED.
func TestTransition_CrossProviderDualRead(t *testing.T) {
	oldGCP := newEnvelopeCipher(&fakeWrapper{}, tmpl, tagGCP, 1)     // the pre-migration provider
	newVault := newEnvelopeCipher(&fakeWrapper{}, tmpl, tagVault, 1) // the provider we switch TO
	tid := uuid.New()

	// A ciphertext written by the OLD provider before the switch.
	oldBlob, err := oldGCP.Encrypt(tid, []byte("pre-migration-secret"))
	if err != nil {
		t.Fatalf("old encrypt: %v", err)
	}
	// The migration cipher: writes with vault (new), but keeps the gcp reader alive for dual-read.
	tc := &transitionCipher{writer: newVault, readers: []*envelopeCipher{oldGCP}}
	// New writes are vault-tagged.
	newBlob, err := tc.Encrypt(tid, []byte("post-migration-secret"))
	if err != nil {
		t.Fatalf("transition encrypt: %v", err)
	}
	if newBlob[1] != byte(tagVault) {
		t.Fatalf("post-switch writes must be vault-tagged, got tag %d", newBlob[1])
	}
	// BOTH old (gcp) and new (vault) blobs decrypt through the transition — the old vault is NOT orphaned.
	if got, err := tc.Decrypt(tid, oldBlob); err != nil || string(got) != "pre-migration-secret" {
		t.Fatalf("dual-read: old-provider blob must still decrypt; got %q err %v", got, err)
	}
	if got, err := tc.Decrypt(tid, newBlob); err != nil || string(got) != "post-migration-secret" {
		t.Fatalf("dual-read: new-provider blob must decrypt; got %q err %v", got, err)
	}
	// Falsification of the falsification: WITHOUT the legacy reader, the old blob is unreadable (would orphan it).
	single := &transitionCipher{writer: newVault}
	if _, err := single.Decrypt(tid, oldBlob); err == nil {
		t.Fatal("a single-reader transition must NOT decrypt the old-provider blob (proves the reader set is load-bearing)")
	}
}

// #7: require-KMS makes localCipher unreachable — New() fails closed without a provider.
func TestNewFromConfig_RequireKMS(t *testing.T) {
	// require-KMS + no provider → refuse to boot (never the dev master key).
	if _, err := NewFromConfig(Config{RequireKMS: true}); err == nil {
		t.Fatal("require-KMS with no provider must fail closed (localCipher unreachable)")
	}
	// require-KMS + a master key but STILL no provider → still refuses (the master key is not an escape hatch).
	master := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	if _, err := NewFromConfig(Config{RequireKMS: true, MasterKeyB64: master}); err == nil {
		t.Fatal("require-KMS must refuse even with a master key present")
	}
	// Without require-KMS, no provider → local cipher builds (dev path unaffected).
	if c, err := NewFromConfig(Config{MasterKeyB64: master}); err != nil || c == nil {
		t.Fatalf("non-require-KMS local path must build: %v", err)
	}
	// require-KMS + a working vault provider (single-key) → boots (the probe round-trips against the loopback).
	v := vaultTestServer(t)
	c, err := NewFromConfig(Config{
		RequireKMS: true, Provider: "vault", KeyName: "single-transit-key",
		VaultAddr: v.addr, VaultToken: func(context.Context) (string, error) { return vaultTestToken, nil },
	})
	if err != nil {
		t.Fatalf("require-KMS with a working vault provider must boot: %v", err)
	}
	// And it actually encrypts/decrypts end-to-end.
	tid := uuid.New()
	blob, err := c.Encrypt(tid, []byte("s"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if got, err := c.Decrypt(tid, blob); err != nil || string(got) != "s" {
		t.Fatalf("round-trip through require-KMS vault: got %q err %v", got, err)
	}
}

// zeroCaptureWrapper retains a reference to the DEK slice it sees, so a test can assert the caller zeroed it.
type zeroCaptureWrapper struct {
	fakeWrapper
	lastWrapDEK   []byte // the plaintext (DEK) slice passed to Wrap
	lastUnwrapDEK []byte // the DEK slice returned from Unwrap
}

func (z *zeroCaptureWrapper) Wrap(ctx context.Context, keyName string, pt, aad []byte) ([]byte, error) {
	z.lastWrapDEK = pt // same backing array the envelope will zero on return
	return z.fakeWrapper.Wrap(ctx, keyName, pt, aad)
}

func (z *zeroCaptureWrapper) Unwrap(ctx context.Context, keyName string, ct, aad []byte) ([]byte, error) {
	out, err := z.fakeWrapper.Unwrap(ctx, keyName, ct, aad)
	z.lastUnwrapDEK = out
	return out, err
}

// #8: the DEK is zeroized after use on BOTH the Encrypt and Decrypt paths (defer zero(dek) still fires).
func TestEnvelope_DEKZeroized(t *testing.T) {
	z := &zeroCaptureWrapper{}
	e := newEnvelopeCipher(z, tmpl, tagVault, 1)
	tid := uuid.New()
	ct, err := e.Encrypt(tid, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !isAllZero(z.lastWrapDEK) {
		t.Fatalf("Encrypt must zeroize the DEK after wrapping; got %x", z.lastWrapDEK)
	}
	if _, err := e.Decrypt(tid, ct); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !isAllZero(z.lastUnwrapDEK) {
		t.Fatalf("Decrypt must zeroize the DEK after unwrapping; got %x", z.lastUnwrapDEK)
	}
}

func isAllZero(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
