package connector

// §6.11 SOAR slice C C-2 — Microsoft Defender for Endpoint (MDE) machine-action client. Auth via OAuth2
// client credentials; resolve a host to a machine id; read machineAction history (the PreCheck signal);
// isolate / unisolate. tokenURL/apiBase/scope are injectable so the client is testable against a mock
// and portable. Note the MDE API is a DIFFERENT surface than the Graph alert-pull: base
// `api.securitycenter.microsoft.com`, scope `.../.default`, requiring the Machine.Isolate permission.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
)

// mdeAllowedHostSuffixes is the D-1 allowlist: a config-driven MDE base URL is validated against these
// expected Microsoft hosts before any real containment call — defense-in-depth OVER netsafe, so even a
// hostile base URL that resolves to a public IP cannot be a non-Microsoft endpoint.
var mdeAllowedHostSuffixes = []string{
	".securitycenter.microsoft.com",
	".security.microsoft.com",
}

// ValidateMDEBaseURL checks a config-driven MDE API base URL is an absolute https URL on an expected
// Microsoft host (D-1). Prod wiring calls this before constructing a Defender action client; a bad
// override fails closed rather than dialing an attacker endpoint.
func ValidateMDEBaseURL(base string) error {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("MDE base URL must be an absolute https URL")
	}
	host := strings.ToLower(u.Hostname())
	for _, suffix := range mdeAllowedHostSuffixes {
		if host == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(host, suffix) {
			return nil
		}
	}
	return fmt.Errorf("MDE base URL host %q is not an allowed Microsoft endpoint", host)
}

// defenderClient calls the MDE machine-action API using OAuth2 client credentials.
type defenderClient struct {
	tokenURL string
	apiBase  string
	scope    string
	clientID string
	secret   string
	http     *http.Client

	token   string
	expires time.Time
}

// newDefenderClient builds the client. hc==nil uses a netsafe.SafeClient (SSRF-safe) in production;
// tests inject a plain client to reach a loopback mock. scope defaults to the MDE .default scope.
func newDefenderClient(tokenURL, apiBase, scope, clientID, secret string, hc *http.Client) *defenderClient {
	if hc == nil {
		hc = netsafe.SafeClient(30 * time.Second)
	}
	if scope == "" {
		scope = "https://api.securitycenter.microsoft.com/.default"
	}
	return &defenderClient{
		tokenURL: tokenURL, apiBase: strings.TrimRight(apiBase, "/"), scope: scope,
		clientID: clientID, secret: secret, http: hc,
	}
}

func (c *defenderClient) accessToken(ctx context.Context) (string, error) {
	if c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.secret},
		"scope":         {c.scope},
		"grant_type":    {"client_credentials"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mde token: status %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", err
	}
	c.token = tr.AccessToken
	ttl := tr.ExpiresIn
	if ttl <= 0 {
		ttl = 3600
	}
	c.expires = time.Now().Add(time.Duration(ttl-60) * time.Second)
	return c.token, nil
}

func (c *defenderClient) do(ctx context.Context, method, path string, body map[string]any) (*http.Response, error) {
	tok, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiBase+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

// odataQuote escapes a value for safe embedding inside an OData single-quoted string literal by doubling
// the single quote (per the OData spec). Without it, a crafted hostname (which can derive from attacker-
// influenced telemetry) could break out of the $filter literal and resolve the WRONG machine — i.e. isolate
// the wrong endpoint (M-1, round #34). url.QueryEscape only handles URL transport, not OData literal syntax.
func odataQuote(s string) string { return strings.ReplaceAll(s, "'", "''") }

// resolveMachineID returns the MDE machine id for a device DNS name.
func (c *defenderClient) resolveMachineID(ctx context.Context, hostname string) (string, error) {
	q := "/api/machines?$filter=" + url.QueryEscape("computerDnsName eq '"+odataQuote(hostname)+"'") + "&$top=1"
	resp, err := c.do(ctx, http.MethodGet, q, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mde machines lookup: status %d", resp.StatusCode)
	}
	var out struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if len(out.Value) == 0 {
		return "", fmt.Errorf("mde: no machine for host %q", hostname)
	}
	return out.Value[0].ID, nil
}

// machineActionStatus is the subset of an MDE machineAction we read for PreCheck. Status is one of
// Pending | InProgress | Succeeded | Failed | Cancelled | TimeOut.
type machineActionStatus struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

// latestMachineAction returns the most recent machineAction of a type for a machine (found=false if
// none). PreCheck reads this: a matching Isolate in Pending|InProgress|Succeeded = already-requested,
// which is what makes crash-while-Pending resume-safe (C-3) — the in-flight action is visible before
// the machine ever reaches a terminal isolated state.
func (c *defenderClient) latestMachineAction(ctx context.Context, machineID, actionType string) (*machineActionStatus, bool, error) {
	f := "machineId eq '" + odataQuote(machineID) + "' and type eq '" + actionType + "'"
	q := "/api/machineactions?$filter=" + url.QueryEscape(f) + "&$orderby=" + url.QueryEscape("creationDateTime desc") + "&$top=1"
	resp, err := c.do(ctx, http.MethodGet, q, nil)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("mde machineactions: status %d", resp.StatusCode)
	}
	var out struct {
		Value []machineActionStatus `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, false, err
	}
	if len(out.Value) == 0 {
		return nil, false, nil
	}
	return &out.Value[0], true, nil
}

// isolate submits a Full isolation and returns the machineAction id (async — the action starts Pending).
func (c *defenderClient) isolate(ctx context.Context, machineID, comment string) (string, error) {
	return c.postAction(ctx, "/api/machines/"+machineID+"/isolate", map[string]any{"Comment": comment, "IsolationType": "Full"})
}

// unisolate reverses an isolation and returns the machineAction id.
func (c *defenderClient) unisolate(ctx context.Context, machineID, comment string) (string, error) {
	return c.postAction(ctx, "/api/machines/"+machineID+"/unisolate", map[string]any{"Comment": comment})
}

func (c *defenderClient) postAction(ctx context.Context, path string, body map[string]any) (string, error) {
	resp, err := c.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("mde action %s: status %d", path, resp.StatusCode)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("mde action %s: no action id in response", path)
	}
	return out.ID, nil
}
