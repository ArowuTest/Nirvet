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
	"os"
	"strings"

	"github.com/google/uuid"
)

// SecretCipher encrypts and decrypts connector credentials, scoped per tenant.
type SecretCipher interface {
	Encrypt(tenantID uuid.UUID, plaintext []byte) ([]byte, error)
	Decrypt(tenantID uuid.UUID, ciphertext []byte) ([]byte, error)
}

const cipherKeyVersion byte = 1

type localCipher struct {
	aead cipher.AEAD
}

func NewLocal(masterKeyB64 string, log *slog.Logger) (SecretCipher, error) {
	return newLocalCipher(masterKeyB64, log)
}

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
	aad := tenantID[:]
	sealed := c.aead.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, 1+len(nonce)+len(sealed))
	out = append(out, cipherKeyVersion)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

func (c *localCipher) Decrypt(tenantID uuid.UUID, ciphertext []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	aad := tenantID[:]
	if len(ciphertext) >= 1+ns && ciphertext[0] == cipherKeyVersion {
		if pt, err := c.aead.Open(nil, ciphertext[1:1+ns], ciphertext[1+ns:], aad); err == nil {
			return pt, nil
		}
	}
	if len(ciphertext) < ns {
		return nil, errors.New("crypto: ciphertext too short")
	}
	return c.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], aad)
}

type Config struct {
	Provider        string
	KeyName         string
	MasterKeyB64    string
	RequireKMS      bool
	KeyGen          byte
	VaultAddr       string
	VaultMount      string
	VaultToken      tokenSource
	HSMModulePath   string
	HSMSlotID       string
	HSMTokenLabel   string
	HSMProbeKeyName string
	HSMPIN          string
	Log             *slog.Logger
}

var errRequireKMSNoProvider = errors.New(
	"crypto: NIRVET_CRYPTO_REQUIRE_KMS=true but no KMS provider is configured — refusing to boot on the local " +
		"master key. Set NIRVET_CRYPTO_PROVIDER (gcp|vault|pkcs11) + the provider configuration. localCipher is " +
		"UNREACHABLE in require-KMS mode.")

func New(kmsKeyName, masterKeyB64 string, log *slog.Logger) (SecretCipher, error) {
	return NewFromConfig(Config{KeyName: kmsKeyName, MasterKeyB64: masterKeyB64, Log: log})
}

func NewFromConfig(cfg Config) (SecretCipher, error) {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	provider := strings.TrimSpace(cfg.Provider)
	if provider == "" && cfg.KeyName != "" {
		provider = "gcp"
	}
	if cfg.RequireKMS && provider == "" {
		return nil, errRequireKMSNoProvider
	}
	if provider == "" {
		return NewLocal(cfg.MasterKeyB64, cfg.Log)
	}
	if provider == "pkcs11" && !strings.Contains(cfg.KeyName, tenantPlaceholder) {
		return nil, errors.New("crypto: pkcs11 provider requires NIRVET_KMS_KEY_NAME to contain {tenant}; a shared HSM KEK does not satisfy per-tenant isolation")
	}

	wrapper, tag, err := buildWrapper(provider, cfg)
	if err != nil {
		return nil, err
	}
	keyGen := cfg.KeyGen
	if keyGen == 0 {
		keyGen = 1
	}
	env := newEnvelopeCipher(wrapper, cfg.KeyName, tag, keyGen)

	probeKey := cfg.KeyName
	shouldProbe := !strings.Contains(cfg.KeyName, tenantPlaceholder)
	if tag == tagPKCS11 {
		probeKey = firstNonBlank(cfg.HSMProbeKeyName, os.Getenv(defaultPKCS11ProbeKeyEnv))
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

func buildWrapper(provider string, cfg Config) (keyWrapper, providerTag, error) {
	tctx, cancel := context.WithTimeout(context.Background(), kmsOpTimeout)
	defer cancel()
	switch provider {
	case "gcp":
		kms := newGCPKMS()
		if _, err := kms.token(tctx); err != nil {
			return nil, 0, err
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
			return nil, 0, err
		}
		return newVaultTransit(cfg.VaultAddr, cfg.VaultMount, tok), tagVault, nil
	case "pkcs11":
		return buildPKCS11Wrapper(cfg)
	default:
		return nil, 0, fmt.Errorf("crypto: unknown KMS provider %q (want gcp|vault|pkcs11)", provider)
	}
}
