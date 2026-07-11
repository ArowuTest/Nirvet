package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
)

// graphClient talks to Microsoft Graph using the OAuth2 client-credentials flow.
// TokenURL and GraphURL are injectable so the client is testable against a mock
// server and unchanged in production (portability).
type graphClient struct {
	tokenURL string
	graphURL string
	clientID string
	secret   string
	http     *http.Client

	token   string
	expires time.Time
}

func newGraphClient(tokenURL, graphURL, clientID, secret string, hc *http.Client) *graphClient {
	if hc == nil {
		hc = netsafe.SafeClient(30 * time.Second) // SSRF-safe: a misconfigured token/graph URL can't reach internal hosts (R6)
	}
	return &graphClient{tokenURL: tokenURL, graphURL: strings.TrimRight(graphURL, "/"), clientID: clientID, secret: secret, http: hc}
}

// msLoginTokenURL builds the Entra/AAD client-credentials token endpoint for a given directory (tenant) ID.
// The tenant ID is path-escaped (C-1): it originates from per-connector config (Credentials.AzureTenant), and a
// value containing '/', '?', or '#' would otherwise reshape the URL path (path-injection / endpoint pivot). All
// four callers (defender/entra actioners, entra guard, poller) route through here so the escaping can't drift.
func msLoginTokenURL(azureTenant string) string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(azureTenant))
}

func (c *graphClient) accessToken(ctx context.Context) (string, error) {
	if c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.secret},
		"scope":         {"https://graph.microsoft.com/.default"},
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
		return "", fmt.Errorf("msgraph token: status %d", resp.StatusCode)
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
	c.expires = time.Now().Add(time.Duration(ttl-60) * time.Second) // refresh a minute early
	return c.token, nil
}

// graphAlert is the subset of a Graph security alert we ingest.
type graphAlert struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Severity        string   `json:"severity"`
	Category        string   `json:"category"`
	CreatedDateTime string   `json:"createdDateTime"`
	DeviceName      string   `json:"deviceName"`
	AccountName     string   `json:"accountName"`
	MitreTechniques []string `json:"mitreTechniques"`
}

// fetchAlerts pulls security alerts created after `since` (RFC3339), following
// pagination up to a bounded number of pages. On 429 it returns the Retry-After
// as an error so the poller backs off to the next tick.
func (c *graphClient) fetchAlerts(ctx context.Context, since string) ([]graphAlert, error) {
	tok, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	next := c.graphURL + "/security/alerts_v2?$top=50"
	if since != "" {
		next += "&$filter=" + url.QueryEscape("createdDateTime gt "+since)
	}
	// C-3: @odata.nextLink is server-supplied. netsafe.SafeClient already blocks internal IPs at dial time, but a
	// compromised/malicious Graph response could point nextLink at an *external* attacker host — and we attach the
	// bearer token to every page fetch, so following it off-host would leak the token. Pin every page to the same
	// host as the configured graph endpoint.
	gu, err := url.Parse(c.graphURL)
	if err != nil || gu.Hostname() == "" {
		return nil, fmt.Errorf("msgraph: invalid graph base URL")
	}
	graphHost := gu.Hostname()
	var out []graphAlert
	for page := 0; next != "" && page < 20; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := c.http.Do(req)
		if err != nil {
			return out, err
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			ra := resp.Header.Get("Retry-After")
			resp.Body.Close()
			secs, _ := strconv.Atoi(ra)
			return out, fmt.Errorf("msgraph: rate limited, retry after %ds", secs)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return out, fmt.Errorf("msgraph alerts: status %d", resp.StatusCode)
		}
		var body struct {
			Value    []graphAlert `json:"value"`
			NextLink string       `json:"@odata.nextLink"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if err != nil {
			return out, err
		}
		out = append(out, body.Value...)
		if body.NextLink != "" {
			nu, perr := url.Parse(body.NextLink)
			if perr != nil || !strings.EqualFold(nu.Hostname(), graphHost) {
				return out, fmt.Errorf("msgraph: refusing @odata.nextLink to unexpected host (want %s)", graphHost)
			}
		}
		next = body.NextLink
	}
	return out, nil
}
