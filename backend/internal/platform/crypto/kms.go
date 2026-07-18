package crypto

// A1 go-live blocker — GCP Cloud KMS envelope encryption (ADR-0004). Closes the single-master-key blast radius:
// each Encrypt generates a fresh 32-byte DEK, AES-256-GCM-seals the plaintext under it (tenant_id as AAD, keeping
// the tenant binding), then WRAPS the DEK with the tenant's OWN KMS CryptoKey. A per-agency key means one leaked
// key never decrypts another agency's vault — actual key separation, not just AAD binding.
//
// Reviewer gate conditions (build/GOLIVE_KMS_ENVELOPE_ENCRYPTION_GATE.md) folded in:
//   M1 fail-closed  — a KMS wrap/unwrap failure hard-errors; there is NO fallback to localCipher/the master key.
//   M2 dispatch     — Decrypt routes on the stored version byte; a v2 blob that fails unwrap NEVER tries a v1 open.
//   M3 bounds       — the v2 parser bounds-checks every field; a truncated/tampered blob is a clean error, no panic.
//   M4 three-way    — New(): KMS+master → dual-read transition; KMS-only → pure; neither → local.
//   M5 provisioning — runtime never creates/destroys keys (only :encrypt/:decrypt); keys pre-provisioned at onboarding.
//   SHOULD          — tenant_id is also bound as AAD on the KMS wrap call (belt-and-suspenders atop the per-tenant KEK).
//
// Transport is REST via netsafe.SafeClient (cloudkms.googleapis.com is public) — no gRPC SDK, matching the repo's
// connector/blobstore pattern and keeping the wrapper httptest-fakeable. The GCP access-token source is wired at
// PROVISIONING (Workload Identity / ADC); until then New() fails fast at boot when a KMS key is configured.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
	"github.com/google/uuid"
)

// cipherKeyVersionKMS is the stored-layout discriminator for envelope (KMS) ciphertexts. localCipher owns version 1;
// this owns 2. Decrypt dispatches on this byte (M2) so v1 and v2 blobs coexist during the dual-read cutover.
const cipherKeyVersionKMS byte = 2

const (
	defaultKMSEndpoint = "https://cloudkms.googleapis.com/v1"
	tenantPlaceholder  = "{tenant}" // in the key-name template → per-tenant CryptoKey
	kmsOpTimeout       = 15 * time.Second
)

// keyWrapper wraps/unwraps a DEK with a KMS CryptoKey. aad is bound into the KMS operation too (SHOULD). The gcpKMS
// impl is REST; tests inject a fake, so the envelope logic needs no GCP.
type keyWrapper interface {
	Wrap(ctx context.Context, keyName string, plaintext, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, keyName string, ciphertext, aad []byte) ([]byte, error)
}

// envelopeCipher is the SecretCipher backed by KMS-wrapped per-op DEKs. Writes/reads version 2 only.
type envelopeCipher struct {
	wrapper     keyWrapper
	keyTemplate string // full CryptoKey resource name; contains {tenant} for per-tenant separation, else single-key
}

func newEnvelopeCipher(w keyWrapper, keyTemplate string) *envelopeCipher {
	return &envelopeCipher{wrapper: w, keyTemplate: keyTemplate}
}

// keyNameFor resolves the tenant's CryptoKey. With {tenant} it is per-tenant (key separation); without, single-key
// (a strict improvement over localCipher but NOT multi-agency separation — pilot-only, documented in the gate).
func (e *envelopeCipher) keyNameFor(tenantID uuid.UUID) string {
	if strings.Contains(e.keyTemplate, tenantPlaceholder) {
		return strings.ReplaceAll(e.keyTemplate, tenantPlaceholder, tenantID.String())
	}
	return e.keyTemplate
}

func (e *envelopeCipher) Encrypt(tenantID uuid.UUID, plaintext []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), kmsOpTimeout)
	defer cancel()
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	aead, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := tenantID[:] // tenant binding on the data key
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	wrapped, err := e.wrapper.Wrap(ctx, e.keyNameFor(tenantID), dek, aad)
	if err != nil {
		// M1: fail closed. A wrap failure NEVER falls back to a shared/local key — that would re-open the exact
		// blast radius this slice closes.
		return nil, fmt.Errorf("crypto: KMS wrap failed (fail-closed, no local fallback): %w", err)
	}
	if len(wrapped) > 0xFFFF {
		return nil, errors.New("crypto: wrapped DEK exceeds uint16 length field")
	}
	// Layout: [version=2][uint16 len(wrapped)][wrapped DEK][nonce][gcm ciphertext].
	out := make([]byte, 0, 1+2+len(wrapped)+len(nonce)+len(sealed))
	out = append(out, cipherKeyVersionKMS)
	out = binary.BigEndian.AppendUint16(out, uint16(len(wrapped)))
	out = append(out, wrapped...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

func (e *envelopeCipher) Decrypt(tenantID uuid.UUID, ciphertext []byte) ([]byte, error) {
	// M3: bounds-check every field before slicing; a truncated/tampered blob is a clean error, never an index panic.
	if len(ciphertext) < 3 || ciphertext[0] != cipherKeyVersionKMS {
		return nil, errors.New("crypto: not a v2 (KMS) ciphertext")
	}
	wl := int(binary.BigEndian.Uint16(ciphertext[1:3]))
	pos := 3
	if len(ciphertext) < pos+wl {
		return nil, errors.New("crypto: v2 ciphertext truncated (wrapped DEK)")
	}
	wrapped := ciphertext[pos : pos+wl]
	pos += wl
	ctx, cancel := context.WithTimeout(context.Background(), kmsOpTimeout)
	defer cancel()
	aad := tenantID[:]
	dek, err := e.wrapper.Unwrap(ctx, e.keyNameFor(tenantID), wrapped, aad)
	if err != nil {
		// M1/M2: a KMS unwrap failure is terminal — never attempt a local/v1 open of a v2 blob.
		return nil, fmt.Errorf("crypto: KMS unwrap failed (fail-closed): %w", err)
	}
	aead, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(ciphertext) < pos+ns {
		return nil, errors.New("crypto: v2 ciphertext truncated (nonce)")
	}
	nonce := ciphertext[pos : pos+ns]
	sealed := ciphertext[pos+ns:]
	return aead.Open(nil, nonce, sealed, aad)
}

// transitionCipher is the dual-read cutover cipher (M4 KMS+master path). Encrypt always emits v2; Decrypt dispatches
// on the version byte so pre-cutover v1 (localCipher) blobs keep opening while new writes are KMS-wrapped v2.
type transitionCipher struct {
	writer *envelopeCipher
	local  *localCipher
}

func (t *transitionCipher) Encrypt(tenantID uuid.UUID, plaintext []byte) ([]byte, error) {
	// M1: always the KMS writer; a wrap failure errors, it does NOT fall back to the local master key.
	return t.writer.Encrypt(tenantID, plaintext)
}

func (t *transitionCipher) Decrypt(tenantID uuid.UUID, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("crypto: empty ciphertext")
	}
	if ciphertext[0] == cipherKeyVersionKMS {
		return t.writer.Decrypt(tenantID, ciphertext) // M2: no fallback for a v2 blob
	}
	// v1 (version byte 1) and pre-version legacy blobs are handled by localCipher's own dual-layout Decrypt.
	return t.local.Decrypt(tenantID, ciphertext)
}

// gcm builds an AES-256-GCM AEAD from a 32-byte data key.
func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ---------------------------------------------------------------------------------------------------------------
// gcpKMS — the REST keyWrapper against Cloud KMS :encrypt / :decrypt via SafeClient. Token source is wired at
// provisioning; until then the default fails fast, so a configured-but-unprovisioned KMS never silently starts.

type tokenSource func(context.Context) (string, error)

// errKMSNotProvisioned is the fail-fast boot error when a KMS key is configured but no GCP token source is wired yet.
var errKMSNotProvisioned = errors.New(
	"crypto: NIRVET_KMS_KEY_NAME is set but the GCP token source is not provisioned — wire a Workload Identity/ADC " +
		"token source (build/GOLIVE_KMS_ENVELOPE_ENCRYPTION_GATE.md, provision-later); until then unset " +
		"NIRVET_KMS_KEY_NAME and set a persistent NIRVET_SECRET_MASTER_KEY")

func notProvisionedToken(context.Context) (string, error) { return "", errKMSNotProvisioned }

type gcpKMS struct {
	endpoint string // https://cloudkms.googleapis.com/v1 (no trailing slash)
	token    tokenSource
	http     *http.Client
}

// newGCPKMS builds the production wrapper: public KMS endpoint, SafeClient, and the not-yet-provisioned token source.
func newGCPKMS() *gcpKMS {
	return &gcpKMS{endpoint: defaultKMSEndpoint, token: notProvisionedToken, http: netsafe.SafeClient(kmsOpTimeout)}
}

func (g *gcpKMS) Wrap(ctx context.Context, keyName string, plaintext, aad []byte) ([]byte, error) {
	var out struct {
		Ciphertext string `json:"ciphertext"`
	}
	body := map[string]string{
		"plaintext":                   base64.StdEncoding.EncodeToString(plaintext),
		"additionalAuthenticatedData": base64.StdEncoding.EncodeToString(aad),
	}
	if err := g.call(ctx, keyName+":encrypt", body, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Ciphertext)
}

func (g *gcpKMS) Unwrap(ctx context.Context, keyName string, ciphertext, aad []byte) ([]byte, error) {
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	body := map[string]string{
		"ciphertext":                  base64.StdEncoding.EncodeToString(ciphertext),
		"additionalAuthenticatedData": base64.StdEncoding.EncodeToString(aad),
	}
	if err := g.call(ctx, keyName+":decrypt", body, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Plaintext)
}

func (g *gcpKMS) call(ctx context.Context, pathAndVerb string, body any, out any) error {
	tok, err := g.token(ctx)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint+"/"+pathAndVerb, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.http.Do(req)
	if err != nil {
		return fmt.Errorf("crypto: KMS request: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("crypto: KMS %s: status %d: %s", pathAndVerb, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	if err := json.Unmarshal(rb, out); err != nil {
		return fmt.Errorf("crypto: KMS %s: bad response: %w", pathAndVerb, err)
	}
	return nil
}
