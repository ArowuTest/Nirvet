package connector

// §6.11 G1 #2 — CrowdStrike Falcon EDR containment client. OAuth2 client-credentials (POST {base}/oauth2/token →
// bearer, cached to expiry) like Entra's token flow. Device containment is ASYNC: contain/lift return a pending
// status and the device transitions containment_pending→contained (or lift_containment_pending→normal), so the
// actioner mirrors Defender's Confirm-poll rather than Okta's synchronous lifecycle. The API base is region-
// specific (US-1 default; GovCloud for sovereign). netsafe.SafeClient blocks internal egress in prod; tests inject.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
)

// crowdStrikeClient calls the Falcon API.
type crowdStrikeClient struct {
	base     string // https://api.crowdstrike.com (region-specific), no trailing slash
	clientID string
	secret   string
	http     *http.Client

	token   string
	expires time.Time
}

func newCrowdStrikeClient(base, clientID, secret string, hc *http.Client) *crowdStrikeClient {
	if hc == nil {
		hc = netsafe.SafeClient(30 * time.Second)
	}
	if base == "" {
		base = "https://api.crowdstrike.com" // US-1 default
	}
	return &crowdStrikeClient{base: strings.TrimRight(base, "/"), clientID: clientID, secret: secret, http: hc}
}

func (c *crowdStrikeClient) accessToken(ctx context.Context) (string, error) {
	if c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	form := url.Values{"client_id": {c.clientID}, "client_secret": {c.secret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("crowdstrike token: status %d", resp.StatusCode)
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
		ttl = 1800
	}
	c.expires = time.Now().Add(time.Duration(ttl-60) * time.Second)
	return c.token, nil
}

func (c *crowdStrikeClient) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	tok, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

// resolveDeviceID maps a hostname to a Falcon device id (AID). A raw device id ("device:<id>") is used directly.
func (c *crowdStrikeClient) resolveDeviceID(ctx context.Context, ref string) (string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/devices/queries/devices/v1?filter="+url.QueryEscape("hostname:'"+ref+"'"), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("crowdstrike device query: status %d", resp.StatusCode)
	}
	var out struct {
		Resources []string `json:"resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if len(out.Resources) == 0 {
		return "", fmt.Errorf("crowdstrike: no device for hostname %q", ref)
	}
	return out.Resources[0], nil
}

// deviceStatus reads a device's containment status: "normal" | "containment_pending" | "contained" |
// "lift_containment_pending". found=false if the device id is unknown.
func (c *crowdStrikeClient) deviceStatus(ctx context.Context, deviceID string) (status string, found bool, err error) {
	resp, err := c.do(ctx, http.MethodGet, "/devices/entities/devices/v2?ids="+url.QueryEscape(deviceID), nil)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("crowdstrike device get: status %d", resp.StatusCode)
	}
	var out struct {
		Resources []struct {
			Status string `json:"status"`
		} `json:"resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", false, err
	}
	if len(out.Resources) == 0 {
		return "", false, nil
	}
	return strings.ToLower(strings.TrimSpace(out.Resources[0].Status)), true, nil
}

// deviceAction submits an async containment action ("contain" | "lift_containment") for a device. Returns nil on
// accepted (200/202); the device then transitions asynchronously (poll via deviceStatus in Confirm).
func (c *crowdStrikeClient) deviceAction(ctx context.Context, deviceID, action string) error {
	resp, err := c.do(ctx, http.MethodPost, "/devices/entities/devices-actions/v2?action_name="+url.QueryEscape(action),
		map[string]any{"ids": []string{deviceID}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("crowdstrike %s: status %d", action, resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------
// IOC (custom indicator) management — the FLEET-WIDE block surface. A 'prevent' indicator on a hash stops that
// file executing on EVERY endpoint in the tenant, which is why cs_block_hash carries fleet_wide=true and can
// never auto-run (see the FleetWide gate). Indicator create/delete are SYNCHRONOUS → the actioner's Confirm=nil.

// findIndicator returns the id of an ACTIVE indicator for (type, value), found=false if none. Used by the
// block PreCheck (already-blocked ⇒ goal-met) and by the reverse fallback.
func (c *crowdStrikeClient) findIndicator(ctx context.Context, iocType, value string) (id string, found bool, err error) {
	filter := iocType + ":'" + value + "'"
	resp, err := c.do(ctx, http.MethodGet, "/iocs/queries/indicators/v1?filter="+url.QueryEscape(filter), nil)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("crowdstrike ioc query: status %d", resp.StatusCode)
	}
	var out struct {
		Resources []string `json:"resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", false, err
	}
	if len(out.Resources) == 0 {
		return "", false, nil
	}
	return out.Resources[0], true, nil
}

// createIndicator creates a 'prevent' (block) indicator for a hash across the tenant. Returns the BARE indicator
// id (the G-1 action_id / the reverse's delete key). Synchronous.
func (c *crowdStrikeClient) createIndicator(ctx context.Context, iocType, value, comment string) (string, error) {
	body := map[string]any{
		"indicators": []map[string]any{{
			"type": iocType, "value": value, "action": "prevent", "severity": "high",
			"platforms": []string{"windows", "mac", "linux"}, "applied_globally": true, "comment": comment,
		}},
	}
	resp, err := c.do(ctx, http.MethodPost, "/iocs/entities/indicators/v1", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("crowdstrike ioc create: status %d", resp.StatusCode)
	}
	var out struct {
		Resources []struct {
			ID string `json:"id"`
		} `json:"resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if len(out.Resources) == 0 || out.Resources[0].ID == "" {
		return "", fmt.Errorf("crowdstrike ioc create: no indicator id returned")
	}
	return out.Resources[0].ID, nil
}

// deleteIndicator removes an indicator by id (the reverse of a block: delete-what-we-made). A 404 is treated as
// already-gone by the caller, not an error here.
func (c *crowdStrikeClient) deleteIndicator(ctx context.Context, id string) (status int, err error) {
	resp, err := c.do(ctx, http.MethodDelete, "/iocs/entities/indicators/v1?ids="+url.QueryEscape(id), nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return resp.StatusCode, fmt.Errorf("crowdstrike ioc delete: status %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
