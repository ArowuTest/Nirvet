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

// Config selects and configures the cipher backend (KMS provider abstraction). It supersedes the positional New()
// (kept below as a thin backward-compatible wrapper).
type Config struct {
	Provider        string       // "" (→ local, or gcp when KeyName is set) | "gcp" | "vault" | "pkcs11"
	KeyName         string       // key template; contains {tenant} for per-tenant/per-agency separation, else single-key
	MasterKeyB64    string       // dev/transition v1 master key (enables dual-read of legacy v1 blobs)
	RequireKMS      bool         // production/sovereign: refuse to boot on localCipher (gate 2b)
	KeyGen          byte         // current provider key generation stamped into new blobs (default 1; bumps on migration)
	VaultAddr       string       // vault provider: NIRVET_VAULT_ADDR (operator infra)
	VaultMount      string       // vault provider: transit mount path (default "transit")
	VaultToken      tokenSource  // vault provider: injected token source (tests); nil → read NIRVET_VAULT_TOKEN from env
	HSMModulePath   string       // pkcs11 provider: module path; empty → NIRVET_HSM_MODULE_PATH
	HSMSlotID       string       // pkcs11 provider: decimal slot ID; empty → NIRVET_HSM_SLOT_ID
	HSMTokenLabel   string       // pkcs11 provider: token label; empty → NIRVET_HSM_TOKEN_LABEL
	HSMProbeKeyName string       // pkcs11 provider: pre-provisioned boot-probe KEK label; empty → NIRVET_HSM_PROBE_KEY_LABEL
	HSMPIN          string       // pkcs11 provider: injected PIN for tests only; empty → NIRVET_HSM_PIN secret
	Log             *slog.Logger // nil → discard
}

// errRequireKMSNoProvider is the fail-closed boot error for require-KMS mode with no provider (gate 2b / test #7).
var errRequireKMSNoProvider = errors.New(
	"crypto: NIRVET_CRYPTO_REQUIRE_KMS=true but no KMS provider is configured — refusing to boot on the local " +
		"master key. Set NIRVET_CRYPTO_PROVIDER (gcp|vault|pkcs11) + the provider configuration. localCipher is " +
		"UNREACHABLE in require-KMS mode.")

// New is the backward-compatible positional constructor: it infers the gcp provider when kmsKeyName is set, else the
// local cipher, with require-KMS off. New code should call NewFromConfig.
func New(kmsKeyName, masterKeyB64 string, log *slog.Logger) (SecretCipher, error) {
	return NewFromConfig(Config{KeyName: kmsKeyName, MasterKeyB64: masterKeyB64, Log: log})
}

// NewFromConfig builds the cipher for the selected provider. Ordering of guarantees:
//   - require-KMS with no provider → fail closed (localCipher unreachable, gate 2b).
//   - no provider → local cipher (dev/pilot single master key).
//   - a provider → build its keyWrapper (fail-fast if the token/creds source is unprovisioned; NO local fallback,
//     M1), run a real wrap/unwrap boot probe where a deterministic probe key exists, then either the pure envelope
//     cipher or, with a master key, the dual-read transitionCipher (writes v2, still reads legacy v1).
//
// Every ciphertext is stamped with the provider tag + key generation, so a later provider switch is a safe
// transitionCipher dual-read (gate 2c) rather than a big-bang swap that orphans a vault.
func NewFromConfig(cfg Config) (SecretCipher, error) {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	provider := cfg.Provider
	if provider == "" && cfg.KeyName != "" {
		provider = "gcp" // backward-compat: a bare KeyName means the legacy GCP KMS path
	}
	if cfg.RequireKMS && provider == "" {
		return nil, errRequireKMSNoProvider // gate 2b / test #7 — localCipher must be unreachable
	}
	if provider == "" {
		return NewLocal(cfg.MasterKeyB64, cfg.Log) // dev/pilot; not reachable under require-KMS
	}

	wrapper, tag, err := buildWrapper(provider, cfg)
	if err != nil {
		return nil, err // fail-fast (unprovisioned creds / unknown provider) — never a silent local fallback (M1)
	}
	keyGen := cfg.KeyGen
	if keyGen == 0 {
		keyGen = 1
	}
	env := newEnvelopeCipher(wrapper, cfg.KeyName, tag, keyGen)

	// A PKCS#11 deployment always supplies a separately provisioned probe KEK. That gives per-tenant HSM mode a
	// real on-token wrap+unwrap check at boot without guessing a tenant ID. Other providers retain the existing
	// single-key probe; per-tenant GCP/Vault keys are verified during tenant onboarding.
	probeKey := cfg.KeyName
	shouldProbe := !strings.Contains(cfg.KeyName, tenantPlaceholder)
	if tag == tagPKCS11 {
		probeKey = strings.TrimSpace(cfg.HSMProbeKeyName)
		if probeKey == "" {
			return nil, errors.New("crypto: pkcs11 provider requires NIRVET_HSM_PROBE_KEY_LABEL for a real wrap/unwrap boot probe")
		}
		shouldProbe = true
	}
	if shouldProbe {
		pctx, pcancel := context.WithTimeout(context.Background(), kmsOpTimeout)
		defer pcancel()
		probeEnv := newEnvelopeCipher(wrapper, probeKey, tag, keyGen)
		if err := probeEnv.bootProbe(pctx); err != nil {
			return nil, err
		}
		cfg.Log.Info("crypto: KMS boot probe OK (wrap+unwrap verified)", "provider", tag.String())
	} else {
		cfg.Log.Info("crypto: KMS per-tenant key template — boot probe skipped (per-agency; verified at onboarding)", "provider", tag.String())
	}

	if cfg.MasterKeyB64 == "" {
		return env, nil
	}
	local, err := newLocalCipher(cfg.MasterKeyB64, cfg.Log)
	if err != nil {
		return nil, err
	}
	return &transitionCipher{writer: env, local: local}, nil
}

// buildWrapper constructs the selected provider's keyWrapper and its provider tag, failing fast when the credential
// source is unprovisioned (so a configured-but-unprovisioned provider never silently starts on the master key).
func buildWrapper(provider string, cfg Config) (keyWrapper, providerTag, error) {
	tctx, cancel := context.WithTimeout(context.Background(), kmsOpTimeout)
	defer cancel()
	switch provider {
	case "gcp":
		kms := newGCPKMS()
		if _, err := kms.token(tctx); err != nil {
			return nil, 0, err // not-provisioned → fail fast (M1: never degrade to the shared master key)
		}
		return kms, tagGCP, nil
	case "vault":
		if cfg.VaultAddr == "" {
			return nil, 0, errors.New("crypto: vault provider requires NIRVET_VAULT_ADDR")
		}
		tok := cfg.VaultToken
		if tok == nil {
			tok = vaultTokenFromEnv
		}
		if _, err := tok(tctx); err != nil {
			return nil, 0, err // token not provisioned → fail fast
		}
		return newVaultTransit(cfg.VaultAddr, cfg.VaultMount, tok), tagVault, nil
	case "pkcs11":
		return buildPKCS11Wrapper(cfg)
	default:
		return nil, 0, fmt.Errorf("crypto: unknown KMS provider %q (want gcp|vault|pkcs11)", provider)
	}
}
