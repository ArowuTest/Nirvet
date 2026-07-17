package connector

// §6.11 G1 #2 — CrowdStrike Falcon EDR host-containment Actioners (cs_isolate_host ⇄ cs_release_host). This slice
// delivers host containment — the #1 EDR response. cs_block_hash/cs_allow_hash (IOC, tenant-wide blast radius per
// CS-FLAG) and cs_kill_process (RTR, non-reversible → correctly not auto-runnable) are deliberate follow-ups, NOT
// registered here (unregistered = honest simulate).
//
// Containment is ASYNC (contain→containment_pending→contained), so each verb carries a Confirm that polls the
// DEVICE status (mirrors Defender's reconciler; unlike Okta's synchronous lifecycle). PreCheck reads the multi-
// valued status and is fail-SAFE toward CONTAINED for the isolate verb:
//   - CS-MA1: isolate over `lift_containment_pending` RE-CONTAINS (cancels the in-flight lift) — a no-op there is a
//     fail-OPEN (host mid-release ends uncontained despite an explicit isolate). Symmetric release over
//     `containment_pending` no-ops (leaves the host contained — the safe direction for a release).
//   - Terminal-state (D2, like Okta): already-`contained` isolate records changed=false, so ReverseRun (which gates
//     on changed=true) never lifts a containment we did not cause (foreign-contained host stays contained).
// action_id is the BARE device id (MA-2 analog; the Confirm poll key). D5 guard runs at the supervisor seam first.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ArowuTest/nirvet/internal/soar"
)

// CrowdStrikeActioner builds the Falcon containment Actioners. Endpoints/creds injectable for tests; prod leaves
// them empty so the region base URL + OAuth pair come from the vault-decrypted Credentials bundle, http nil→SafeClient.
type CrowdStrikeActioner struct {
	base     string
	clientID string
	secret   string
	http     *http.Client
}

// NewCrowdStrikeActioner builds the factory. Empty base/clientID/secret ⇒ read per-call from the tenant creds.
func NewCrowdStrikeActioner(base, clientID, secret string, hc *http.Client) *CrowdStrikeActioner {
	return &CrowdStrikeActioner{base: base, clientID: clientID, secret: secret, http: hc}
}

// Actioners returns isolate ⇄ release. Each is Class-High, reversible with the symmetric inverse, PreCheck (resume-
// safe), and carries a Confirm that polls until the device reaches the verb's terminal state.
func (a *CrowdStrikeActioner) Actioners() []soar.Actioner {
	return []soar.Actioner{
		{
			ConnectorKey: string(KindCrowdStrike), Action: "cs_isolate_host",
			PreCheck: true, Reversible: true, Inverse: "cs_release_host",
			Fn: func(ctx context.Context, creds []byte, target string, _ map[string]any) (string, map[string]any, error) {
				return a.act(ctx, creds, target, true)
			},
			Confirm: a.confirmState("contained"),
		},
		{
			ConnectorKey: string(KindCrowdStrike), Action: "cs_release_host",
			PreCheck: true, Reversible: true, Inverse: "cs_isolate_host",
			Fn: func(ctx context.Context, creds []byte, target string, _ map[string]any) (string, map[string]any, error) {
				return a.act(ctx, creds, target, false)
			},
			Confirm: a.confirmState("normal"),
		},
	}
}

// act contains (contain=true) or lifts (contain=false) a device with the multi-state fail-safe.
func (a *CrowdStrikeActioner) act(ctx context.Context, creds []byte, target string, contain bool) (string, map[string]any, error) {
	client, deviceID, err := a.resolve(ctx, creds, target)
	if err != nil {
		return "", nil, err
	}
	status, found, err := client.deviceStatus(ctx, deviceID)
	if err != nil {
		return "", nil, err
	}
	if !found {
		return "", nil, fmt.Errorf("crowdstrike: device %q not found", deviceID)
	}
	if contain { // ISOLATE
		switch status {
		case "contained", "containment_pending":
			// Goal met (D2 fail-safe): already contained / in-flight contain. No call, changed=false → reverse
			// won't lift a containment we can't prove we caused.
			return "already:" + deviceID, csGoalMet(deviceID, status), nil
		case "lift_containment_pending":
			// CS-MA1: mid-release, but the operator wants CONTAINED. Re-issue contain (cancel the in-flight lift) —
			// err toward contained, never leave a host uncontained after an explicit isolate.
			if err := client.deviceAction(ctx, deviceID, "contain"); err != nil {
				return "", csFail(deviceID), err
			}
			return deviceID, csChanged(deviceID), nil
		default: // normal
			if err := client.deviceAction(ctx, deviceID, "contain"); err != nil {
				return "", csFail(deviceID), err
			}
			return deviceID, csChanged(deviceID), nil
		}
	}
	// RELEASE (also the reverse inverse)
	switch status {
	case "normal", "lift_containment_pending":
		// Already uncontained / in-flight lift → goal met, no call.
		return "already:" + deviceID, csGoalMet(deviceID, status), nil
	case "containment_pending":
		// CS-MA1 symmetric: leave a host heading-to-contained — the safe direction for a release is to NOT lift.
		return "already:" + deviceID, csGoalMet(deviceID, status), nil
	default: // contained
		if err := client.deviceAction(ctx, deviceID, "lift_containment"); err != nil {
			return "", csFail(deviceID), err
		}
		return deviceID, csChanged(deviceID), nil
	}
}

// confirmState returns a Confirm that polls the device until it reaches `target` (contained for isolate, normal for
// release). A transitioning (*_pending) status is not-terminal; any OTHER terminal status is a failure of this verb.
func (a *CrowdStrikeActioner) confirmState(target string) func(context.Context, []byte, string) (bool, bool, string, error) {
	return func(ctx context.Context, creds []byte, actionRef string) (bool, bool, string, error) {
		client, err := a.clientOnly(creds)
		if err != nil {
			return false, false, "", err
		}
		status, found, err := client.deviceStatus(ctx, actionRef)
		if err != nil {
			return false, false, "", err
		}
		if !found {
			return false, false, "NotFound", nil
		}
		switch status {
		case target:
			return true, true, status, nil
		case "containment_pending", "lift_containment_pending":
			return false, false, status, nil // still transitioning — not terminal
		default:
			return true, false, status, nil // reached a terminal state that is NOT this verb's target → failed
		}
	}
}

func (a *CrowdStrikeActioner) resolve(ctx context.Context, creds []byte, target string) (*crowdStrikeClient, string, error) {
	client, err := a.clientOnly(creds)
	if err != nil {
		return nil, "", err
	}
	ref := strings.TrimSpace(target)
	if id := strings.TrimPrefix(ref, "device:"); id != ref {
		return client, strings.TrimSpace(id), nil
	}
	host := strings.TrimSpace(strings.TrimPrefix(ref, "host:"))
	if host == "" {
		return nil, "", fmt.Errorf("crowdstrike: empty target")
	}
	deviceID, err := client.resolveDeviceID(ctx, host)
	if err != nil {
		return nil, "", err
	}
	return client, deviceID, nil
}

func (a *CrowdStrikeActioner) clientOnly(creds []byte) (*crowdStrikeClient, error) {
	var cb Credentials
	if err := json.Unmarshal(creds, &cb); err != nil {
		return nil, fmt.Errorf("crowdstrike: bad credentials bundle: %w", err)
	}
	base := a.base
	if base == "" {
		base = cb.CrowdStrikeBaseURL
	}
	id := a.clientID
	if id == "" {
		id = cb.ClientID
	}
	secret := a.secret
	if secret == "" {
		secret = cb.ClientSecret
	}
	if id == "" || secret == "" {
		return nil, fmt.Errorf("crowdstrike: missing client credentials")
	}
	return newCrowdStrikeClient(base, id, secret, a.http), nil
}

// csGoalMet/csChanged/csFail build priorState. action_id = BARE device id (MA-2) in the goal-met + changed paths
// (the Confirm poll key). csGoalMet records changed=false (no effect we caused); csChanged records changed=true.
func csGoalMet(deviceID, status string) map[string]any {
	return map[string]any{"changed": false, "device_id": deviceID, "status": status, "action_id": deviceID}
}
func csChanged(deviceID string) map[string]any {
	return map[string]any{"changed": true, "device_id": deviceID, "action_id": deviceID}
}
func csFail(deviceID string) map[string]any {
	return map[string]any{"changed": false, "device_id": deviceID}
}
