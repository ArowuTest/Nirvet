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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"

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

// NewLocal builds a local cipher from a base64-encoded 32-byte key. If key is
// empty, an ephemeral key is generated (dev convenience) and a warning is logged;
// secrets then do not survive a restart.
func NewLocal(masterKeyB64 string, log *slog.Logger) (SecretCipher, error) {
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
	if len(ciphertext) < 1+ns {
		return nil, errors.New("crypto: ciphertext too short")
	}
	if ciphertext[0] != cipherKeyVersion {
		return nil, fmt.Errorf("crypto: unsupported key version %d", ciphertext[0])
	}
	nonce, sealed := ciphertext[1:1+ns], ciphertext[1+ns:]
	aad := tenantID[:]
	return c.aead.Open(nil, nonce, sealed, aad)
}

// kmsCipher is the production backend that wraps data keys with GCP Cloud KMS.
// TODO(ADR-0004): implement envelope encryption via cloud.google.com/go/kms.
//  1. generate a random DEK, AES-256-GCM encrypt plaintext (tenant_id as AAD),
//  2. wrap the DEK with the tenant's KMS CryptoKey, store {wrappedDEK, ciphertext},
//  3. on decrypt, unwrap DEK via KMS then open. Cache decrypted secrets only in
//     memory for the duration of a connector run.
type kmsCipher struct{ keyName string }

var errKMSNotImplemented = errors.New("crypto: GCP KMS cipher not yet implemented (ADR-0004); until it is, unset NIRVET_KMS_KEY_NAME and set a persistent NIRVET_SECRET_MASTER_KEY")

// NewKMS returns the KMS-backed cipher. It is NOT yet implemented, so it fails at
// construction (fail-fast at startup) rather than returning a cipher that would error
// on every connector-credential / MFA-secret operation at runtime. Wired in before
// go-live when GCP credentials are available (see the kmsCipher TODO above).
func NewKMS(keyName string) (SecretCipher, error) {
	return nil, errKMSNotImplemented
}

func (c *kmsCipher) Encrypt(uuid.UUID, []byte) ([]byte, error) { return nil, errKMSNotImplemented }
func (c *kmsCipher) Decrypt(uuid.UUID, []byte) ([]byte, error) { return nil, errKMSNotImplemented }

// New selects the cipher based on configuration: KMS if a key name is set,
// otherwise the local cipher.
func New(kmsKeyName, masterKeyB64 string, log *slog.Logger) (SecretCipher, error) {
	if kmsKeyName != "" {
		return NewKMS(kmsKeyName)
	}
	return NewLocal(masterKeyB64, log)
}
