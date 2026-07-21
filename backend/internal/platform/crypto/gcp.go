package crypto

// gcpKMS — the REST keyWrapper against Cloud KMS :encrypt / :decrypt via SafeClient (Cloud KMS is a PUBLIC endpoint,
// so SafeClient is correct here — unlike on-prem Vault). Token source is wired at provisioning; until then the
// default fails fast, so a configured-but-unprovisioned KMS never silently starts. Wrap/unwrap ONLY — the KEK
// (the CryptoKey) never leaves GCP; all DEK↔plaintext AEAD stays in envelopeCipher (enforced by the boundary fence).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
)

// tokenSource yields a bearer/credential token for a provider call. Shared by the gcp + vault providers; the source
// is wired at provisioning (Workload Identity / env / mounted secret) and is never persisted or logged.
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
	// #nosec G704 -- operator-config URL, not user input; SSRF-safe (netsafe waiver).
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint+"/"+pathAndVerb, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	// #nosec G704 -- operator-config URL, not user input; SSRF-safe (netsafe waiver).
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
