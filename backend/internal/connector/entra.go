package connector

// §6.11 SOAR second vendor E-1 — Microsoft Entra ID (Graph) identity-containment client. Client-credentials
// auth (Graph .default scope); read a user's accountEnabled + directory roles (for the D5 protected-identity
// guard) and enabled-member counts (last-of-role); disable/enable the account. tokenURL/apiBase/scope are
// injectable so the client is testable against a mock and portable. Graph disable is a synchronous PATCH
// (204 = done) — unlike MDE's async machineAction — so the reconciler needs no async confirm here.

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

// graphAllowedHostSuffixes is the D-1-style allowlist for the config-driven Graph base URL — validated before
// any real identity call, defense-in-depth over netsafe (a hostile base URL can't be a non-Microsoft endpoint).
var graphAllowedHostSuffixes = []string{".graph.microsoft.com"}
var graphAllowedHostsExact = []string{"graph.microsoft.com", "graph.microsoft.us"}

// ValidateGraphBaseURL checks a config-driven Graph base URL is absolute-https on an expected Microsoft Graph
// host. Prod wiring calls this before constructing an Entra client; a bad override fails closed.
func ValidateGraphBaseURL(base string) error {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("Graph base URL must be an absolute https URL")
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range graphAllowedHostsExact {
		if host == h {
			return nil
		}
	}
	for _, s := range graphAllowedHostSuffixes {
		if strings.HasSuffix(host, s) {
			return nil
		}
	}
	return fmt.Errorf("Graph base URL host %q is not an allowed Microsoft Graph endpoint", host)
}

// entraClient calls Microsoft Graph using OAuth2 client credentials.
type entraClient struct {
	tokenURL string
	apiBase  string
	scope    string
	clientID string
	secret   string
	http     *http.Client

	token   string
	expires time.Time
}

func newEntraClient(tokenURL, apiBase, scope, clientID, secret string, hc *http.Client) *entraClient {
	if hc == nil {
		hc = netsafe.SafeClient(30 * time.Second)
	}
	if scope == "" {
		scope = "https://graph.microsoft.com/.default"
	}
	return &entraClient{
		tokenURL: tokenURL, apiBase: strings.TrimRight(apiBase, "/"), scope: scope,
		clientID: clientID, secret: secret, http: hc,
	}
}

func (c *entraClient) accessToken(ctx context.Context) (string, error) {
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
		return "", fmt.Errorf("graph token: status %d", resp.StatusCode)
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

func (c *entraClient) do(ctx context.Context, method, path string, body map[string]any) (*http.Response, error) {
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

// entraUser is the subset of a Graph user we read.
type entraUser struct {
	ID             string `json:"id"`
	AccountEnabled bool   `json:"accountEnabled"`
}

// resolveUser reads a user's object id + accountEnabled by object id or UPN. found=false on 404.
func (c *entraClient) resolveUser(ctx context.Context, ref string) (u entraUser, found bool, err error) {
	resp, err := c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(ref)+"?$select=id,accountEnabled", nil)
	if err != nil {
		return entraUser{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return entraUser{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return entraUser{}, false, fmt.Errorf("graph get user: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return entraUser{}, false, err
	}
	return u, true, nil
}

// setAccountEnabled disables (false) or enables (true) a user account. Synchronous (204).
func (c *entraClient) setAccountEnabled(ctx context.Context, userID string, enabled bool) error {
	resp, err := c.do(ctx, http.MethodPatch, "/users/"+url.PathEscape(userID), map[string]any{"accountEnabled": enabled})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("graph patch accountEnabled: status %d", resp.StatusCode)
	}
	return nil
}

// directoryRole is the subset of a Graph directoryRole we read for the D5 guard.
type directoryRole struct {
	ID             string `json:"id"`
	DisplayName    string `json:"displayName"`
	RoleTemplateID string `json:"roleTemplateId"`
}

// userDirectoryRoles returns the ACTIVE directory roles a user holds (transitive), for the L2 protected-role
// check. Uses the OData cast to directoryRole so only role objects are returned.
func (c *entraClient) userDirectoryRoles(ctx context.Context, userID string) ([]directoryRole, error) {
	resp, err := c.do(ctx, http.MethodGet,
		"/users/"+url.PathEscape(userID)+"/transitiveMemberOf/microsoft.graph.directoryRole?$select=id,displayName,roleTemplateId", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("graph user roles: status %d", resp.StatusCode)
	}
	var out struct {
		Value []directoryRole `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Value, nil
}

// roleEnabledMemberCount counts the ENABLED user members of a directory role — the last-of-role guard (L2).
// Best-effort (TOCTOU): a concurrent disable of another member between this count and our disable could leave
// zero; there is no cross-Graph-API transaction. It meaningfully reduces the risk, it is not an airtight invariant.
func (c *entraClient) roleEnabledMemberCount(ctx context.Context, roleID string) (int, error) {
	resp, err := c.do(ctx, http.MethodGet,
		"/directoryRoles/"+url.PathEscape(roleID)+"/members/microsoft.graph.user?$select=id,accountEnabled", nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("graph role members: status %d", resp.StatusCode)
	}
	var out struct {
		Value []entraUser `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	n := 0
	for _, m := range out.Value {
		if m.AccountEnabled {
			n++
		}
	}
	return n, nil
}
