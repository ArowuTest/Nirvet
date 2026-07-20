package crypto

// KMS provider abstraction (increment 1) — HashiCorp Vault Transit keyWrapper. Vault Transit is the first sovereign/
// on-prem provider behind the existing keyWrapper seam (gate 2a). It does wrap/unwrap ONLY: Wrap POSTs the DEK to
// transit/encrypt and returns the opaque "vault:v1:.." wrapped bytes; Unwrap POSTs them to transit/decrypt and returns
// the DEK. The transit key (the KEK) NEVER leaves Vault (gate §1) — there is no key-export path here, and all
// DEK↔plaintext AEAD stays in envelopeCipher. Per-tenant separation = a transit key per tenant (keyNameFor →
// transit key name).
//
// Transport: Vault is on-prem/sovereign operator INFRASTRUCTURE, addressed by NIRVET_VAULT_ADDR — operator env config
// exactly like the Postgres DSN, NOT tenant-configurable input. On-prem/sovereign Vault deliberately lives at a
// private address that netsafe.SafeClient (SSRF guard for tenant-supplied URLs) would wrongly block, so this client
// is intentionally a plain timeout-bounded client with an auditable netsafe-exempt waiver. The token comes from a
// secure source (env/secret), never the DB, and is never logged.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const defaultVaultMount = "transit"

// errVaultNotProvisioned is the fail-fast boot error when the vault provider is selected but no token is available.
var errVaultNotProvisioned = errors.New(
	"crypto: vault provider selected but the Vault token is not provisioned — supply NIRVET_VAULT_TOKEN via env/" +
		"mounted secret/Vault agent (never the DB); until then select a different provider")

// vaultTokenFromEnv reads the Vault token from env at call time (secure source; never DB, never logged).
func vaultTokenFromEnv(context.Context) (string, error) {
	if t := os.Getenv("NIRVET_VAULT_TOKEN"); t != "" {
		return t, nil
	}
	return "", errVaultNotProvisioned
}

// vaultTransit implements keyWrapper against Vault's Transit secrets engine.
type vaultTransit struct {
	addr  string      // e.g. https://vault.internal:8200 (operator infra; no trailing slash)
	mount string      // transit mount path (default "transit")
	token tokenSource // Vault token from env/secret — never DB, never logged
	http  *http.Client
}

func newVaultTransit(addr, mount string, token tokenSource) *vaultTransit {
	if mount == "" {
		mount = defaultVaultMount
	}
	// Vault addr is operator infrastructure config (NIRVET_VAULT_ADDR), NOT tenant-configurable; on-prem/sovereign
	// Vault is deliberately at a private address that SafeClient would wrongly block. KEK never leaves Vault.
	return &vaultTransit{
		addr:  strings.TrimRight(addr, "/"),
		mount: mount,
		token: token,
		http:  &http.Client{Timeout: kmsOpTimeout}, // netsafe-exempt: operator-config Vault addr, not tenant input (see above)
	}
}

// Wrap sends the DEK to Vault transit/encrypt under keyName and returns the opaque "vault:v1:.." wrapped bytes.
func (v *vaultTransit) Wrap(ctx context.Context, keyName string, plaintext, aad []byte) ([]byte, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	body := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}
	if len(aad) > 0 {
		// associated_data binds the tenant AAD into the Vault operation too (SHOULD, belt-and-suspenders atop the
		// per-tenant transit key + the DEK's own GCM AAD). Requires an AEAD (aes-gcm) transit key on real Vault.
		body["associated_data"] = base64.StdEncoding.EncodeToString(aad)
	}
	if err := v.call(ctx, "encrypt/"+keyName, body, &out); err != nil {
		return nil, err
	}
	if out.Data.Ciphertext == "" {
		return nil, errors.New("crypto: vault encrypt returned empty ciphertext")
	}
	return []byte(out.Data.Ciphertext), nil
}

// Unwrap sends the wrapped bytes to Vault transit/decrypt under keyName and returns the DEK.
func (v *vaultTransit) Unwrap(ctx context.Context, keyName string, ciphertext, aad []byte) ([]byte, error) {
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	body := map[string]string{"ciphertext": string(ciphertext)}
	if len(aad) > 0 {
		body["associated_data"] = base64.StdEncoding.EncodeToString(aad)
	}
	if err := v.call(ctx, "decrypt/"+keyName, body, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Data.Plaintext)
}

func (v *vaultTransit) call(ctx context.Context, pathSuffix string, body any, out any) error {
	tok, err := v.token(ctx)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(body)
	url := v.addr + "/v1/" + v.mount + "/" + pathSuffix
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", tok) // secret; never logged
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("crypto: vault request: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("crypto: vault %s: status %d: %s", pathSuffix, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	if err := json.Unmarshal(rb, out); err != nil {
		return fmt.Errorf("crypto: vault %s: bad response: %w", pathSuffix, err)
	}
	return nil
}
