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
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// cipherKeyVersionKMS is the stored-layout discriminator for envelope (KMS/HSM/Vault) ciphertexts. localCipher owns
// version 1; this owns 2. Decrypt dispatches on this byte (M2) so v1 and v2 blobs coexist during the dual-read cutover.
const cipherKeyVersionKMS byte = 2

const (
	defaultKMSEndpoint = "https://cloudkms.googleapis.com/v1"
	tenantPlaceholder  = "{tenant}" // in the key-name template → per-tenant CryptoKey / transit key / HSM label
	kmsOpTimeout       = 15 * time.Second
)

// providerTag records WHICH wrap/unwrap backend sealed a v2 ciphertext (gate 2c). It is stored in the blob so a
// provider switch is a safe dual-read (each provider decrypts only its own blobs) instead of a big-bang swap that
// mis-unwraps or orphans an existing vault. A ciphertext tagged for one provider fed to another REFUSES loudly.
type providerTag byte

const (
	tagGCP    providerTag = 1 // GCP Cloud KMS (:encrypt/:decrypt REST)
	tagVault  providerTag = 2 // HashiCorp Vault Transit (encrypt/decrypt REST)
	tagPKCS11 providerTag = 3 // PKCS#11 HSM — RESERVED for increment 2 (needs SoftHSM in CI); not yet selectable
)

func (p providerTag) String() string {
	switch p {
	case tagGCP:
		return "gcp"
	case tagVault:
		return "vault"
	case tagPKCS11:
		return "pkcs11"
	default:
		return fmt.Sprintf("provider(%d)", byte(p))
	}
}

// keyWrapper wraps/unwraps a DEK with a KMS/HSM/Vault key-encrypting key (KEK). The KEK NEVER leaves the backend
// (gate §1): Wrap sends the DEK and returns wrapped bytes; Unwrap sends wrapped bytes and returns the DEK. aad is
// bound into the backend operation too (SHOULD). A provider does wrap/unwrap ONLY — no DEK↔plaintext AEAD, no key
// export (enforced by scripts/check-kms-provider-boundary.sh). Impls are REST; tests inject a fake or a loopback.
type keyWrapper interface {
	Wrap(ctx context.Context, keyName string, plaintext, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, keyName string, ciphertext, aad []byte) ([]byte, error)
}

// envelopeCipher is the SecretCipher backed by backend-wrapped per-op DEKs. Writes/reads version 2 only. The DEK
// generation, AES-256-GCM AEAD, per-tenant key resolution, tenant-as-AAD, and zeroize all live HERE — a provider
// never touches plaintext. tag+keyGen are stamped into every blob so cross-provider/cross-generation reads refuse.
type envelopeCipher struct {
	wrapper     keyWrapper
	keyTemplate string      // full key resource name; contains {tenant} for per-tenant separation, else single-key
	tag         providerTag // which backend wrapped — recorded in the ciphertext (2c)
	keyGen      byte        // provider key generation; bumps on a provider/key-namespace migration (2c). Default 1.
}

func newEnvelopeCipher(w keyWrapper, keyTemplate string, tag providerTag, keyGen byte) *envelopeCipher {
	if keyGen == 0 {
		keyGen = 1
	}
	return &envelopeCipher{wrapper: w, keyTemplate: keyTemplate, tag: tag, keyGen: keyGen}
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
	defer zero(dek) // reviewer follow-on (b): best-effort DEK zeroization after use (sovereign defense-in-depth)
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
	// Layout: [version=2][providerTag][keyGen][uint16 len(wrapped)][wrapped DEK][nonce][gcm ciphertext].
	// tag+keyGen (2c) let Decrypt refuse a blob from a different provider/generation instead of mis-unwrapping.
	out := make([]byte, 0, 3+2+len(wrapped)+len(nonce)+len(sealed))
	out = append(out, cipherKeyVersionKMS)
	out = append(out, byte(e.tag))
	out = append(out, e.keyGen)
	out = binary.BigEndian.AppendUint16(out, uint16(len(wrapped)))
	out = append(out, wrapped...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

func (e *envelopeCipher) Decrypt(tenantID uuid.UUID, ciphertext []byte) ([]byte, error) {
	// M3: bounds-check every field before slicing; a truncated/tampered blob is a clean error, never an index panic.
	if len(ciphertext) < 5 || ciphertext[0] != cipherKeyVersionKMS {
		return nil, errors.New("crypto: not a v2 (KMS) ciphertext")
	}
	// 2c / gate test #4: refuse a blob wrapped by a DIFFERENT provider or key-generation. Unwrapping provider-A's
	// ciphertext with provider-B (or gen-M with gen-N) must fail LOUDLY, never silently mis-unwrap or return garbage.
	if tag := providerTag(ciphertext[1]); tag != e.tag {
		return nil, fmt.Errorf("crypto: provider mismatch (blob wrapped by %s, this cipher is %s) — refusing to unwrap", tag, e.tag)
	}
	if gen := ciphertext[2]; gen != e.keyGen {
		return nil, fmt.Errorf("crypto: key-generation mismatch (blob=gen%d, cipher=gen%d) — refusing to unwrap", gen, e.keyGen)
	}
	wl := int(binary.BigEndian.Uint16(ciphertext[3:5]))
	pos := 5
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
	defer zero(dek) // reviewer follow-on (b): best-effort DEK zeroization after use
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

// bootProbe verifies the configured CryptoKey actually wraps AND unwraps at boot (reviewer LOW follow-on).
// Single-key mode only: without {tenant} in the template there is exactly one key, so one probe proves the
// whole configuration — key name, IAM permission, and both :encrypt and :decrypt. In per-tenant mode the keys
// are per-agency and cannot all be probed at boot; the caller logs the skip instead.
//
// Fail-closed on ANY mismatch: a deploy whose key can wrap but not unwrap (asymmetric IAM — roles/cloudkms
// encrypter without decrypter is a real GCP misconfig) would otherwise WRITE vault entries nobody can ever
// read back, and surface only at first customer decrypt.
func (e *envelopeCipher) bootProbe(ctx context.Context) error {
	probe := make([]byte, 32)
	if _, err := rand.Read(probe); err != nil {
		return err
	}
	defer zero(probe)
	aad := []byte("nirvet-kms-boot-probe")
	keyName := e.keyTemplate // single-key mode: template IS the key name
	wrapped, err := e.wrapper.Wrap(ctx, keyName, probe, aad)
	if err != nil {
		return fmt.Errorf("crypto: KMS boot probe wrap failed (fail-closed — key/IAM misconfig?): %w", err)
	}
	got, err := e.wrapper.Unwrap(ctx, keyName, wrapped, aad)
	if err != nil {
		return fmt.Errorf("crypto: KMS boot probe unwrap failed (fail-closed — encrypter-without-decrypter IAM would write unreadable vault entries): %w", err)
	}
	defer zero(got)
	if !bytes.Equal(got, probe) {
		return errors.New("crypto: KMS boot probe round-trip mismatch (fail-closed)")
	}
	return nil
}

// transitionCipher is the dual-read cutover cipher. Encrypt always writes with the CURRENT provider (writer, v2).
// Decrypt dispatches: a v1 blob → localCipher (the pre-KMS master key); a v2 blob → the reader whose (tag,keyGen)
// matches the blob. `readers` holds legacy-PROVIDER envelope ciphers kept alive during a provider migration (gate
// 2c / test #6: after switching provider, old-provider ciphertext still decrypts — no orphaned vault). The writer is
// always a candidate reader, so single-provider transitions (M4 KMS+master) need no explicit readers.
type transitionCipher struct {
	writer  *envelopeCipher   // current provider — all new writes (v2, tagged writer.tag/keyGen)
	readers []*envelopeCipher // additional legacy-provider readers (old tag/keyGen) for a provider→provider migration
	local   *localCipher      // v1 reader (pre-KMS master key); may be nil for a pure provider→provider migration
}

func (t *transitionCipher) Encrypt(tenantID uuid.UUID, plaintext []byte) ([]byte, error) {
	// M1: always the current provider writer; a wrap failure errors, it does NOT fall back to the local master key
	// or a legacy reader.
	return t.writer.Encrypt(tenantID, plaintext)
}

// allReaders is the writer followed by any legacy-provider readers — the candidates a v2 blob may match by tag+gen.
func (t *transitionCipher) allReaders() []*envelopeCipher {
	return append([]*envelopeCipher{t.writer}, t.readers...)
}

func (t *transitionCipher) Decrypt(tenantID uuid.UUID, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("crypto: empty ciphertext")
	}
	if ciphertext[0] == cipherKeyVersionKMS {
		if len(ciphertext) < 3 {
			return nil, errors.New("crypto: v2 ciphertext truncated (tag)")
		}
		tag, gen := providerTag(ciphertext[1]), ciphertext[2]
		for _, r := range t.allReaders() {
			if r.tag == tag && r.keyGen == gen {
				return r.Decrypt(tenantID, ciphertext) // M2: no fallback to another cipher on unwrap failure
			}
		}
		// A v2 blob whose provider/generation matches NO configured reader is refused — never mis-routed to the
		// local master key or a mismatched provider (that would silently mis-unwrap or fail confusingly).
		return nil, fmt.Errorf("crypto: no configured provider matches this ciphertext (tag=%s gen=%d) — refusing", tag, gen)
	}
	// v1 (version byte 1) and pre-version legacy blobs are handled by localCipher's own dual-layout Decrypt.
	if t.local == nil {
		return nil, errors.New("crypto: v1 ciphertext but no local reader configured (provider-only migration) — refusing")
	}
	return t.local.Decrypt(tenantID, ciphertext)
}

// zero overwrites a byte slice (best-effort scrub of a data key after use). Go's GC may still hold copies, but
// zeroing the DEK we control shortens its lifetime in memory — cheap defense-in-depth for a sovereign vault.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// gcm builds an AES-256-GCM AEAD from a 32-byte data key.
func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
