package connector

// §6.11 G1 first non-Microsoft response vendor — Okta identity-containment client. Auth is an SSWS API token
// (Authorization: SSWS <token>); the org base URL is per-tenant (https://{org}.okta.com). Lifecycle transitions
// (suspend/unsuspend) are synchronous 200 responses, so the reconciler needs no async confirm (Confirm=nil),
// mirroring Entra's synchronous PATCH. The client is intentionally minimal: read a user's id+status, transition
// lifecycle, revoke sessions. netsafe.SafeClient blocks internal egress in production; tests inject their own hc.

import (
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

// oktaClient calls the Okta Management API with an SSWS token.
type oktaClient struct {
	orgURL string // https://{org}.okta.com (no trailing slash)
	token  string // SSWS API token
	http   *http.Client
}

func newOktaClient(orgURL, token string, hc *http.Client) *oktaClient {
	if hc == nil {
		hc = netsafe.SafeClient(30 * time.Second)
	}
	return &oktaClient{orgURL: strings.TrimRight(orgURL, "/"), token: token, http: hc}
}

func (c *oktaClient) do(ctx context.Context, method, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.orgURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "SSWS "+c.token)
	req.Header.Set("Accept", "application/json")
	return c.http.Do(req)
}

// oktaUser is the subset of an Okta user we read. status is MULTI-VALUED (STAGED, PROVISIONED, ACTIVE,
// LOCKED_OUT, PASSWORD_EXPIRED, SUSPENDED, DEPROVISIONED) — the actioner's terminal-state fail-safe keys on it.
type oktaUser struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// resolveUser reads a user's id + status by id or login. found=false on 404.
func (c *oktaClient) resolveUser(ctx context.Context, ref string) (oktaUser, bool, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/users/"+url.PathEscape(ref))
	if err != nil {
		return oktaUser{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return oktaUser{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return oktaUser{}, false, fmt.Errorf("okta get user: status %d", resp.StatusCode)
	}
	var u oktaUser
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return oktaUser{}, false, err
	}
	return u, true, nil
}

// lifecycle POSTs a lifecycle transition ("suspend"/"unsuspend"). Synchronous: 200 = done. A 400 means the user
// was not in a valid state for the transition — the actioner's PreCheck prevents that by only transitioning from
// the expected state, so a 400 here is a genuine error, not an expected already-in-state.
func (c *oktaClient) lifecycle(ctx context.Context, userID, action string) error {
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/users/"+url.PathEscape(userID)+"/lifecycle/"+action)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("okta %s: status %d", action, resp.StatusCode)
	}
	return nil
}

// revokeSessions clears a user's sessions (and OAuth tokens). Naturally idempotent (a second call on a user with
// no sessions still succeeds). 204 = done.
func (c *oktaClient) revokeSessions(ctx context.Context, userID string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/api/v1/users/"+url.PathEscape(userID)+"/sessions?oauthTokens=true")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("okta revoke sessions: status %d", resp.StatusCode)
	}
	return nil
}
