// Package crypto implements the connector-credential vault (ADR-0004).
//
// Connector secrets (OAuth tokens, API keys) are encrypted with AES-256-GCM and
// tenant_id bound into the GCM AAD, so a ciphertext cannot be decrypted under
// another tenant's context. In production the data key is wrapped by GCP KMS; the
// local cipher (dev) holds a single master key. Both satisfy the same interface,
// so connectors are agnostic to the backend.
//
// Secrets exist decrypted only in memory, only at use time. Never log them.
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
)

// SecretCipher encrypts and decrypts connector credentials, scoped per tenant.
type SecretCipher interface {
	// Encrypt seals plaintext for tenantID; the returned bytes are safe to store.
	Encrypt(tenantID uuid.UUID, plaintext []byte) ([]byte, error)
	// Decrypt opens ciphertext for tenantID; fails if the tenant does not match.
	Decrypt(tenantID uuid.UUID, ciphertext []byte) ([]byte, error)
}

// cipherKeyVersion is a 1-byte discriminator prefixed to every ciphertext (R2 vault
// residual). It gives key rotation a hook: a future key can bump the version so decrypt
// can select the right key by the stored byte, without a data migration.
const cipherKeyVersion byte = 1

// localCipher is an AES-256-GCM cipher using a single master key. Dev/MVP only.
type localCipher struct {
	aead cipher.AEAD
}

// NewLocal builds a local cipher (SecretCipher) from a base64-encoded 32-byte key.
func NewLocal(masterKeyB64 string, log *slog.Logger) (SecretCipher, error) {
	return newLocalCipher(masterKeyB64, log)
}

// newLocalCipher builds the concrete *localCipher (used both as the standalone SecretCipher and as the v1 reader
// inside the KMS dual-read transitionCipher). If key is empty, an ephemeral key is generated (dev convenience) and a
// warning is logged; secrets then do not survive a restart.
func newLocalCipher(masterKeyB64 string, log *slog.Logger) (*localCipher, error) {
	var key []byte
	if masterKeyB64 == "" {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if log != nil {
			log.Warn("crypto: NIRVET_SECRET_MASTER_KEY not set — using ephemeral key; stored secrets will not survive restart")
		}
	} else {
		k, err := base64.StdEncoding.DecodeString(masterKeyB64)
		if err != nil {
			return nil, fmt.Errorf("crypto: decode master key: %w", err)
		}
		if len(k) != 32 {
			return nil, errors.New("crypto: master key must be 32 bytes (base64)")
		}
		key = k
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &localCipher{aead: aead}, nil
}

func (c *localCipher) Encrypt(tenantID uuid.UUID, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := tenantID[:] // tenant binding
	sealed := c.aead.Seal(nil, nonce, plaintext, aad)
	// Stored layout: [version byte][nonce][ciphertext]. The version supports rotation.
	out := make([]byte, 0, 1+len(nonce)+len(sealed))
	out = append(out, cipherKeyVersion)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

func (c *localCipher) Decrypt(tenantID uuid.UUID, ciphertext []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	aad := tenantID[:]
	// Current layout: [version][nonce][ciphertext]. Try it when the first byte matches.
	if len(ciphertext) >= 1+ns && ciphertext[0] == cipherKeyVersion {
		if pt, err := c.aead.Open(nil, ciphertext[1:1+ns], ciphertext[1+ns:], aad); err == nil {
			return pt, nil
		}
		// fall through — a rare legacy blob whose first byte happens to equal the version.
	}
	// Legacy layout: [nonce][ciphertext] (pre-version-byte). Back-compat so existing
	// stored secrets (MFA/connector creds) keep decrypting across the version-byte deploy
	// (R2 M-NEW: the version byte must NOT be a data-loss landmine).
	if len(ciphertext) < ns {
		return nil, errors.New("crypto: ciphertext too short")
	}
	return c.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], aad)
}

// New selects the cipher backend (M4 — three-way, for the KMS dual-read cutover). The real envelope cipher +
// gcpKMS wrapper live in kms.go:
//   - kmsKeyName == ""            → local cipher (dev/pilot; single master key).
//   - kmsKeyName + masterKeyB64   → transitionCipher: writes KMS-wrapped v2, still reads legacy v1 (zero-downtime cutover).
//   - kmsKeyName, no masterKeyB64 → pure envelopeCipher (post-cutover; no v1 to read).
//
// A configured-but-unprovisioned KMS fails fast at boot (its token source is not yet wired — provision later).
func New(kmsKeyName, masterKeyB64 string, log *slog.Logger) (SecretCipher, error) {
	if kmsKeyName == "" {
		return NewLocal(masterKeyB64, log)
	}
	kms := newGCPKMS()
	// Fail fast at startup: a KMS-configured deploy whose token source can't be obtained must not silently start
	// (and must never degrade to the shared master key — M1).
	tctx, cancel := context.WithTimeout(context.Background(), kmsOpTimeout)
	defer cancel()
	if _, err := kms.token(tctx); err != nil {
		return nil, err
	}
	env := newEnvelopeCipher(kms, kmsKeyName)
	// Boot probe (reviewer LOW follow-on): in single-key mode one wrap+unwrap round-trip proves key name, IAM,
	// and both KMS verbs before the app serves — an encrypter-without-decrypter IAM misconfig would otherwise
	// write vault entries nobody can read, surfacing only at first customer decrypt. Per-tenant mode has one
	// key per agency and cannot probe them all at boot; skipped with a log line.
	if !strings.Contains(kmsKeyName, tenantPlaceholder) {
		pctx, pcancel := context.WithTimeout(context.Background(), kmsOpTimeout)
		defer pcancel()
		if err := env.bootProbe(pctx); err != nil {
			return nil, err
		}
		log.Info("crypto: KMS single-key boot probe OK (wrap+unwrap round-trip verified)")
	} else {
		log.Info("crypto: KMS per-tenant key template — boot probe skipped (keys are per-agency; verified at onboarding)")
	}
	if masterKeyB64 == "" {
		return env, nil
	}
	local, err := newLocalCipher(masterKeyB64, log)
	if err != nil {
		return nil, err
	}
	return &transitionCipher{writer: env, local: local}, nil
}
