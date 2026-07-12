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

// fetchPaged does a bounded, host-pinned, bearer-authenticated paged GET of a Graph collection endpoint and
// decodes each page's `value` array into T, following `@odata.nextLink` up to a bounded number of pages. It is
// the ONE shared fetch primitive behind every stream (alerts / sign-ins / directory-audits / risky-users) so the
// security properties can't drift per stream:
//   - netsafe.SafeClient blocks internal IPs at dial time (SSRF), AND
//   - C-3: every page (incl. server-supplied @odata.nextLink) is PINNED to the configured graph host — the bearer
//     token is attached to each page, so following an off-host nextLink would leak it.
//   - 429 → return the Retry-After as an error so the poller backs off to the next tick (no busy-retry).
//
// firstPath is the relative path incl. any base query (e.g. "/auditLogs/signIns?$top=50"); filter is an OData
// $filter expression appended with "&" (empty = none).
func fetchPaged[T any](ctx context.Context, c *graphClient, firstPath, filter string) ([]T, error) {
	tok, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	gu, err := url.Parse(c.graphURL)
	if err != nil || gu.Hostname() == "" {
		return nil, fmt.Errorf("msgraph: invalid graph base URL")
	}
	graphHost := gu.Hostname()
	next := c.graphURL + firstPath
	if filter != "" {
		next += "&$filter=" + url.QueryEscape(filter)
	}
	var out []T
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
			return out, fmt.Errorf("msgraph %s: status %d", firstPath, resp.StatusCode)
		}
		var body struct {
			Value    []T    `json:"value"`
			NextLink string `json:"@odata.nextLink"`
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

// fetchAlerts pulls security alerts created after `since` (RFC3339) — pre-formed Defender alerts.
func (c *graphClient) fetchAlerts(ctx context.Context, since string) ([]graphAlert, error) {
	filter := ""
	if since != "" {
		filter = "createdDateTime gt " + since
	}
	return fetchPaged[graphAlert](ctx, c, "/security/alerts_v2?$top=50", filter)
}

// graphSignIn is the subset of an Entra ID sign-in log we ingest (US-030). Raw identity TELEMETRY (not an
// alert) — the stateful detection engine (DET-002) evaluates these for MFA-fatigue / impossible-travel /
// risky-sign-in. Needs AuditLog.Read.All app consent.
type graphSignIn struct {
	ID                    string `json:"id"`
	CreatedDateTime       string `json:"createdDateTime"`
	UserPrincipalName     string `json:"userPrincipalName"`
	UserID                string `json:"userId"`
	AppDisplayName        string `json:"appDisplayName"`
	IPAddress             string `json:"ipAddress"`
	ClientAppUsed         string `json:"clientAppUsed"`
	IsInteractive         bool   `json:"isInteractive"`
	RiskState             string `json:"riskState"`
	RiskLevelDuringSignIn string `json:"riskLevelDuringSignIn"`
	Status                struct {
		ErrorCode         int    `json:"errorCode"`
		FailureReason     string `json:"failureReason"`
		AdditionalDetails string `json:"additionalDetails"`
	} `json:"status"`
	MfaDetail struct {
		AuthMethod string `json:"authMethod"`
		AuthDetail string `json:"authDetail"`
	} `json:"mfaDetail"`
	Location struct {
		City            string `json:"city"`
		CountryOrRegion string `json:"countryOrRegion"`
	} `json:"location"`
}

// fetchSignIns pulls Entra sign-in logs created after `since` (US-030).
func (c *graphClient) fetchSignIns(ctx context.Context, since string) ([]graphSignIn, error) {
	filter := ""
	if since != "" {
		filter = "createdDateTime gt " + since
	}
	return fetchPaged[graphSignIn](ctx, c, "/auditLogs/signIns?$top=50", filter)
}

// graphDirectoryAudit is the subset of an Entra directory audit event we ingest (US-029, M365/identity admin
// changes). Needs AuditLog.Read.All app consent.
type graphDirectoryAudit struct {
	ID                  string `json:"id"`
	ActivityDateTime    string `json:"activityDateTime"`
	ActivityDisplayName string `json:"activityDisplayName"`
	Category            string `json:"category"`
	Result              string `json:"result"`
	InitiatedBy         struct {
		User struct {
			UserPrincipalName string `json:"userPrincipalName"`
			ID                string `json:"id"`
			IPAddress         string `json:"ipAddress"`
		} `json:"user"`
	} `json:"initiatedBy"`
	TargetResources []struct {
		DisplayName       string `json:"displayName"`
		Type              string `json:"type"`
		UserPrincipalName string `json:"userPrincipalName"`
	} `json:"targetResources"`
}

// fetchDirectoryAudits pulls Entra directory audit events after `since` (US-029).
func (c *graphClient) fetchDirectoryAudits(ctx context.Context, since string) ([]graphDirectoryAudit, error) {
	filter := ""
	if since != "" {
		filter = "activityDateTime gt " + since
	}
	return fetchPaged[graphDirectoryAudit](ctx, c, "/auditLogs/directoryAudits?$top=50", filter)
}

// graphRiskyUser is the subset of an Entra Identity Protection risky-user record we ingest (risk signal).
// State, not an event stream — the poller delta-filters on riskLastUpdatedDateTime. Needs
// IdentityRiskyUser.Read.All app consent.
type graphRiskyUser struct {
	ID                      string `json:"id"`
	UserPrincipalName       string `json:"userPrincipalName"`
	RiskLevel               string `json:"riskLevel"`
	RiskState               string `json:"riskState"`
	RiskDetail              string `json:"riskDetail"`
	RiskLastUpdatedDateTime string `json:"riskLastUpdatedDateTime"`
}

// fetchRiskyUsers pulls Entra risky users updated after `since` (risk-signal events).
func (c *graphClient) fetchRiskyUsers(ctx context.Context, since string) ([]graphRiskyUser, error) {
	filter := ""
	if since != "" {
		filter = "riskLastUpdatedDateTime gt " + since
	}
	return fetchPaged[graphRiskyUser](ctx, c, "/identityProtection/riskyUsers?$top=50", filter)
}
