package crypto

// A1 KMS envelope-encryption tests. Envelope logic runs against a fakeWrapper (no GCP); the REST gcpKMS runs against
// a loopback httptest KMS. Proves the reviewer's gate conditions: round-trip, tenant-AAD binding survives envelope,
// per-tenant key routing (real separation, not just AAD), M1 fail-closed / no local fallback, M2 version dispatch,
// M3 bounds, and the M4 three-way New().

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// fakeWrapper is a faithful in-memory keyWrapper: it length-delimits keyName|aad|plaintext so Unwrap can verify BOTH
// the key name AND the aad match (so a wrong key or wrong tenant fails), and records the keyName seen per Wrap.
type fakeWrapper struct {
	wrapKeys   []string
	failWrap   bool
	failUnwrap bool
}

func (f *fakeWrapper) Wrap(_ context.Context, keyName string, pt, aad []byte) ([]byte, error) {
	if f.failWrap {
		return nil, errors.New("fake: wrap denied (no key for tenant)")
	}
	f.wrapKeys = append(f.wrapKeys, keyName)
	var b []byte
	b = binary.BigEndian.AppendUint16(b, uint16(len(keyName)))
	b = append(b, keyName...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(aad)))
	b = append(b, aad...)
	b = append(b, pt...)
	return b, nil
}

func (f *fakeWrapper) Unwrap(_ context.Context, keyName string, ct, aad []byte) ([]byte, error) {
	if f.failUnwrap {
		return nil, errors.New("fake: unwrap denied")
	}
	if len(ct) < 2 {
		return nil, errors.New("fake: short")
	}
	kl := int(binary.BigEndian.Uint16(ct[:2]))
	p := 2
	if len(ct) < p+kl+2 {
		return nil, errors.New("fake: short")
	}
	gotKey := string(ct[p : p+kl])
	p += kl
	al := int(binary.BigEndian.Uint16(ct[p : p+2]))
	p += 2
	if len(ct) < p+al {
		return nil, errors.New("fake: short")
	}
	gotAAD := ct[p : p+al]
	p += al
	if gotKey != keyName {
		return nil, errors.New("fake: key mismatch")
	}
	if !bytes.Equal(gotAAD, aad) {
		return nil, errors.New("fake: aad mismatch")
	}
	return ct[p:], nil
}

const tmpl = "projects/p/locations/l/keyRings/nirvet/cryptoKeys/tenant-{tenant}"

func TestEnvelope_RoundTrip(t *testing.T) {
	e := newEnvelopeCipher(&fakeWrapper{}, tmpl, tagGCP, 1)
	tid := uuid.New()
	pt := []byte("okta-token-abc123")
	ct, err := e.Encrypt(tid, pt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ct[0] != cipherKeyVersionKMS {
		t.Fatalf("ciphertext must start with version byte 2, got %d", ct[0])
	}
	got, err := e.Decrypt(tid, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: %q != %q", got, pt)
	}
}

func TestEnvelope_TenantAADBinding(t *testing.T) {
	// A v2 ciphertext sealed for A must not open under B — the tenant binding survives envelope (GCM AAD +
	// per-tenant key + fake's aad check all diverge).
	e := newEnvelopeCipher(&fakeWrapper{}, tmpl, tagGCP, 1)
	a, b := uuid.New(), uuid.New()
	ct, err := e.Encrypt(a, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := e.Decrypt(b, ct); err == nil {
		t.Fatal("tenant B must NOT decrypt tenant A's v2 ciphertext")
	}
}

func TestEnvelope_PerTenantKeyRouting(t *testing.T) {
	// The actual key-separation proof: A wraps under tenant-A's key, B under tenant-B's — not one shared key.
	fw := &fakeWrapper{}
	e := newEnvelopeCipher(fw, tmpl, tagGCP, 1)
	a, b := uuid.New(), uuid.New()
	if _, err := e.Encrypt(a, []byte("x")); err != nil {
		t.Fatalf("encrypt a: %v", err)
	}
	if _, err := e.Encrypt(b, []byte("y")); err != nil {
		t.Fatalf("encrypt b: %v", err)
	}
	wantA := strings.ReplaceAll(tmpl, tenantPlaceholder, a.String())
	wantB := strings.ReplaceAll(tmpl, tenantPlaceholder, b.String())
	if len(fw.wrapKeys) != 2 || fw.wrapKeys[0] != wantA || fw.wrapKeys[1] != wantB {
		t.Fatalf("per-tenant key routing broken: keys=%v want [%s %s]", fw.wrapKeys, wantA, wantB)
	}
}

func TestEnvelope_FailClosed_NoLocalFallback(t *testing.T) {
	// M1: a wrap failure must hard-error, NOT silently produce a local/shared-key blob.
	e := newEnvelopeCipher(&fakeWrapper{failWrap: true}, tmpl, tagGCP, 1)
	if _, err := e.Encrypt(uuid.New(), []byte("s")); err == nil {
		t.Fatal("M1: Encrypt must fail closed when KMS wrap fails (no local fallback)")
	}
	// M1/M2: a v2 blob whose unwrap fails must error, never fall through to another cipher.
	ok := newEnvelopeCipher(&fakeWrapper{}, tmpl, tagGCP, 1)
	tid := uuid.New()
	ct, _ := ok.Encrypt(tid, []byte("s"))
	broken := newEnvelopeCipher(&fakeWrapper{failUnwrap: true}, tmpl, tagGCP, 1)
	if _, err := broken.Decrypt(tid, ct); err == nil {
		t.Fatal("M1/M2: Decrypt must fail closed when KMS unwrap fails")
	}
}

func TestEnvelope_BoundsCheck(t *testing.T) {
	// M3: truncated / malformed v2 blobs return clean errors, never an index panic.
	e := newEnvelopeCipher(&fakeWrapper{}, tmpl, tagGCP, 1)
	tid := uuid.New()
	full, _ := e.Encrypt(tid, []byte("hello world"))
	for _, n := range []int{0, 1, 2, 3, 4, len(full) - 5, len(full) - 1} {
		if n < 0 || n >= len(full) {
			continue
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("M3: Decrypt panicked on truncated len=%d: %v", n, r)
				}
			}()
			if _, err := e.Decrypt(tid, full[:n]); err == nil {
				t.Fatalf("M3: truncated ciphertext len=%d must error", n)
			}
		}()
	}
	// A non-v2 first byte is rejected by the envelope cipher.
	if _, err := e.Decrypt(tid, []byte{1, 2, 3, 4, 5}); err == nil {
		t.Fatal("M3: envelope cipher must reject a non-v2 blob")
	}
}

func TestTransition_DualRead(t *testing.T) {
	// M4 dual-read: writes are v2 (KMS); reads dispatch on the version byte so legacy v1 (localCipher) blobs still
	// open. M2: a v2 blob is never handed to the local reader.
	local, err := newLocalCipher(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), nil)
	if err != nil {
		t.Fatalf("local: %v", err)
	}
	tc := &transitionCipher{writer: newEnvelopeCipher(&fakeWrapper{}, tmpl, tagGCP, 1), local: local}
	tid := uuid.New()

	// A legacy v1 blob written by the old local cipher must still decrypt through the transition.
	v1, _ := local.Encrypt(tid, []byte("legacy-secret"))
	if got, err := tc.Decrypt(tid, v1); err != nil || string(got) != "legacy-secret" {
		t.Fatalf("dual-read: v1 blob must still decrypt; got %q err %v", got, err)
	}

	// New writes are v2 and round-trip through the transition.
	v2, err := tc.Encrypt(tid, []byte("new-secret"))
	if err != nil {
		t.Fatalf("transition encrypt: %v", err)
	}
	if v2[0] != cipherKeyVersionKMS {
		t.Fatalf("transition Encrypt must emit v2, got version %d", v2[0])
	}
	if got, err := tc.Decrypt(tid, v2); err != nil || string(got) != "new-secret" {
		t.Fatalf("dual-read: v2 blob must decrypt; got %q err %v", got, err)
	}
}

func TestNew_ThreeWay_and_FailFast(t *testing.T) {
	master := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	// neither → local cipher constructs.
	if c, err := New("", master, nil); err != nil || c == nil {
		t.Fatalf("New('', master) must build the local cipher; err=%v", err)
	}
	// KMS configured but token source unprovisioned → fail fast at construction (never a silent shared-key start).
	if _, err := New("projects/p/.../tenant-{tenant}", master, nil); !errors.Is(err, errKMSNotProvisioned) {
		t.Fatalf("New(kmsKey, master) must fail fast as not-provisioned, got %v", err)
	}
	if _, err := New("projects/p/.../k", "", nil); !errors.Is(err, errKMSNotProvisioned) {
		t.Fatalf("New(kmsKey, '') must fail fast as not-provisioned, got %v", err)
	}
}

func TestGCPKMS_REST_RoundTrip(t *testing.T) {
	// The REST wrapper against a loopback KMS: asserts bearer auth + base64 plaintext/AAD marshaling and a
	// reversible :encrypt/:decrypt round-trip. Uses srv.Client() so the loopback call isn't SafeClient-blocked.
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
		_ = json.NewDecoder(r.Body).Decode(&in)
		if strings.HasSuffix(r.URL.Path, ":encrypt") {
			pt, _ := base64.StdEncoding.DecodeString(in["plaintext"])
			if in["additionalAuthenticatedData"] == "" {
				t.Error("KMS :encrypt must receive additionalAuthenticatedData")
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(xor(pt))})
			return
		}
		if strings.HasSuffix(r.URL.Path, ":decrypt") {
			ct, _ := base64.StdEncoding.DecodeString(in["ciphertext"])
			_ = json.NewEncoder(w).Encode(map[string]string{"plaintext": base64.StdEncoding.EncodeToString(xor(ct))})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	g := &gcpKMS{endpoint: srv.URL, token: func(context.Context) (string, error) { return "test-token", nil }, http: srv.Client()}
	dek := bytes.Repeat([]byte{9}, 32)
	aad := []byte("tenant-aad")
	wrapped, err := g.Wrap(context.Background(), "k1", dek, aad)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	got, err := g.Unwrap(context.Background(), "k1", wrapped, aad)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("REST round-trip mismatch")
	}

	// A non-200 from KMS propagates as an error (fail loud).
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer bad.Close()
	g2 := &gcpKMS{endpoint: bad.URL, token: func(context.Context) (string, error) { return "test-token", nil }, http: bad.Client()}
	if _, err := g2.Wrap(context.Background(), "k1", dek, aad); err == nil {
		t.Fatal("KMS 403 must surface as an error")
	}
}

// ── bootProbe (reviewer LOW follow-on: single-key-mode wrap+unwrap probe at boot) ─────────────────────────────

const singleKeyTmpl = "projects/p/locations/l/keyRings/nirvet/cryptoKeys/pilot-single"

func TestBootProbe_SingleKey_OK(t *testing.T) {
	fw := &fakeWrapper{}
	e := newEnvelopeCipher(fw, singleKeyTmpl, tagGCP, 1)
	if err := e.bootProbe(context.Background()); err != nil {
		t.Fatalf("bootProbe: %v", err)
	}
	// The probe must exercise the CONFIGURED key name verbatim (that's what it is proving).
	if len(fw.wrapKeys) != 1 || fw.wrapKeys[0] != singleKeyTmpl {
		t.Fatalf("probe wrapped with %v, want exactly [%s]", fw.wrapKeys, singleKeyTmpl)
	}
}

func TestBootProbe_WrapDenied_Fails(t *testing.T) {
	e := newEnvelopeCipher(&fakeWrapper{failWrap: true}, singleKeyTmpl, tagGCP, 1)
	if err := e.bootProbe(context.Background()); err == nil {
		t.Fatal("bootProbe succeeded with wrap denied — must fail closed")
	}
}

// The exact misconfig the probe exists for: IAM grants encrypter but not decrypter, so the app would
// happily WRITE vault entries that nothing can ever read back.
func TestBootProbe_UnwrapDenied_Fails(t *testing.T) {
	e := newEnvelopeCipher(&fakeWrapper{failUnwrap: true}, singleKeyTmpl, tagGCP, 1)
	if err := e.bootProbe(context.Background()); err == nil {
		t.Fatal("bootProbe succeeded with unwrap denied — must fail closed (encrypter-without-decrypter)")
	}
}

// corruptingWrapper unwraps "successfully" but returns the wrong bytes — the round-trip equality check must catch it.
type corruptingWrapper struct{ fakeWrapper }

func (c *corruptingWrapper) Unwrap(ctx context.Context, keyName string, ct, aad []byte) ([]byte, error) {
	out, err := c.fakeWrapper.Unwrap(ctx, keyName, ct, aad)
	if err != nil {
		return nil, err
	}
	if len(out) > 0 {
		out[0] ^= 0xFF
	}
	return out, nil
}

func TestBootProbe_RoundTripMismatch_Fails(t *testing.T) {
	e := newEnvelopeCipher(&corruptingWrapper{}, singleKeyTmpl, tagGCP, 1)
	if err := e.bootProbe(context.Background()); err == nil {
		t.Fatal("bootProbe succeeded despite round-trip mismatch — must fail closed")
	}
}
