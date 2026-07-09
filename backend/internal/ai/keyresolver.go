package ai

// §6.12 #117 A-5 — the real KeyResolver: unseal an ai_provider.api_key_ref (base64 sealed ciphertext) via the
// shared SecretBox (connector.Vault, KMS-backed). Same pattern as connector credential resolution — the decrypt is
// recorded by the AI-call audit (which logs the provider kind/endpoint that used the key), not a separate row.

import (
	"context"
	"encoding/base64"

	"github.com/google/uuid"
)

// VaultKeyResolver implements KeyResolver against a SecretBox.
type VaultKeyResolver struct{ box SecretBox }

// NewVaultKeyResolver builds the resolver.
func NewVaultKeyResolver(box SecretBox) *VaultKeyResolver { return &VaultKeyResolver{box: box} }

// ResolveKey base64-decodes the stored ref and opens it under its seal scope.
func (v *VaultKeyResolver) ResolveKey(_ context.Context, scope uuid.UUID, ref string) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(ref)
	if err != nil {
		return "", err
	}
	pt, err := v.box.Open(scope, ct)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
