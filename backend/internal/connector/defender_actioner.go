package connector

// §6.11 SOAR slice C C-3 — the two REAL Defender Actioners (isolate_endpoint ⇄ release_endpoint) that
// register into the SOAR supervisor's registry. This is where the crash-safety story becomes concrete:
// each Fn PreChecks the machineAction HISTORY (a matching action in Pending|InProgress|Succeeded =
// already-requested) BEFORE issuing the POST, so a Phase-B re-drive after a crash-while-Pending sees the
// in-flight action and does NOT double-isolate (gate C-3). The observed prior_state.changed drives the
// MUST-3 reverse: an action that found the target already in the end state is a no-op and is not undone.
//
// connector imports soar here (soar does not import connector — no cycle): providing a soar.Actioner is
// implementing soar's plugin seam, wired into the registry at api/worker startup.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ArowuTest/nirvet/internal/soar"
)

// DefenderActioner builds the Defender-for-Endpoint containment Actioners. Endpoints are injectable:
// prod leaves them empty (tokenURL derived per-tenant from azure_tenant, apiBase = the default MDE host,
// http = netsafe.SafeClient); tests point them at a mock MDE server via an injected plain client.
type DefenderActioner struct {
	tokenURL string
	apiBase  string
	scope    string
	http     *http.Client
}

// NewDefenderActioner builds the factory. Empty tokenURL/apiBase/scope select production defaults; a nil
// http client selects netsafe.SafeClient. A non-empty apiBase MUST have passed ValidateMDEBaseURL (D-1).
func NewDefenderActioner(tokenURL, apiBase, scope string, hc *http.Client) *DefenderActioner {
	return &DefenderActioner{tokenURL: tokenURL, apiBase: apiBase, scope: scope, http: hc}
}

// Actioners returns the isolate + release Actioners to register into the SOAR ActionerRegistry. Action
// keys match the seeded soar_action_catalog (isolate_endpoint/release_endpoint, connector_key=defender),
// so supervisor lookup resolves them. Both declare PreCheck (resume-safe) + a symmetric Inverse.
func (d *DefenderActioner) Actioners() []soar.Actioner {
	return []soar.Actioner{
		{
			ConnectorKey: string(KindDefender), Action: "isolate_endpoint",
			PreCheck: true, Reversible: true, Inverse: "release_endpoint",
			Fn: func(ctx context.Context, creds []byte, target string, params map[string]any) (string, map[string]any, error) {
				return d.act(ctx, creds, target, params, "Isolate")
			},
			Confirm: d.confirm,
		},
		{
			ConnectorKey: string(KindDefender), Action: "release_endpoint",
			PreCheck: true, Reversible: true, Inverse: "isolate_endpoint",
			Fn: func(ctx context.Context, creds []byte, target string, params map[string]any) (string, map[string]any, error) {
				return d.act(ctx, creds, target, params, "Unisolate")
			},
			Confirm: d.confirm,
		},
	}
}

// act performs one Defender action (Isolate|Unisolate) with PreCheck-then-POST semantics.
func (d *DefenderActioner) act(ctx context.Context, creds []byte, target string, params map[string]any, actionType string) (string, map[string]any, error) {
	var cb Credentials
	if err := json.Unmarshal(creds, &cb); err != nil {
		return "", nil, fmt.Errorf("defender: bad credentials bundle: %w", err)
	}
	client := d.clientFor(cb)

	machineID, err := targetToMachine(ctx, client, target)
	if err != nil {
		return "", nil, err
	}
	correlator, _ := params[soar.ActionCorrelatorParam].(string)

	// PreCheck (C-3): a matching action already in flight/complete means we must NOT re-POST (history-based,
	// so a crash-while-Pending resume still sees it). Attribution (round #34 H-1b): the action is OURS only
	// if its requestorComment carries THIS step's correlator → changed=true (reverse may release it). A
	// FOREIGN active isolation (another run, Defender auto-investigation, a manual analyst) carries a
	// different/absent correlator → changed=false so reverse never releases a containment we did not create.
	if act, found, err := client.latestMachineAction(ctx, machineID, actionType); err != nil {
		return "", nil, err
	} else if found && mdeActionActive(act.Status) {
		// Round-#34 LOW fold-in: match the DELIMITED correlator token `[nirvet:<corr>]`, not the bare
		// `<run>:<step>` — so `:1` can never be a substring of `:10`. prior_state carries the BARE action id
		// (G-1) for the reconciler to poll, regardless of the human-readable display ref.
		mine := correlator != "" && strings.Contains(act.RequestorComment, correlatorToken(correlator))
		kind := "foreign"
		if mine {
			kind = "own"
		}
		return kind + "-" + strings.ToLower(actionType) + ":" + act.ID,
			map[string]any{"changed": mine, "foreign": !mine, "machine_id": machineID, "precheck_status": act.Status, "action_id": act.ID}, nil
	}

	comment := mdeComment(actionType, params, correlator)
	var ref string
	if actionType == "Isolate" {
		ref, err = client.isolate(ctx, machineID, comment)
	} else {
		ref, err = client.unisolate(ctx, machineID, comment)
	}
	if err != nil {
		return "", map[string]any{"changed": false, "machine_id": machineID}, err
	}
	return ref, map[string]any{"changed": true, "machine_id": machineID, "action_id": ref}, nil
}

// confirm polls the terminal state of a submitted machineAction (completion reconciler, D-3). done=terminal;
// success=Succeeded; a 404/aged-out action is (done=false, "NotFound") — unconfirmable, never a false failure.
func (d *DefenderActioner) confirm(ctx context.Context, creds []byte, actionRef string) (done bool, success bool, status string, err error) {
	var cb Credentials
	if e := json.Unmarshal(creds, &cb); e != nil {
		return false, false, "", fmt.Errorf("defender: bad credentials bundle: %w", e)
	}
	act, code, e := d.clientFor(cb).getMachineAction(ctx, actionRef)
	if e != nil {
		return false, false, "", e
	}
	if code == http.StatusNotFound || act == nil {
		return false, false, "NotFound", nil
	}
	switch strings.ToLower(strings.TrimSpace(act.Status)) {
	case "succeeded":
		return true, true, act.Status, nil
	case "failed", "cancelled", "timeout":
		return true, false, act.Status, nil
	default: // pending | inprogress — not terminal yet
		return false, false, act.Status, nil
	}
}

func (d *DefenderActioner) clientFor(cb Credentials) *defenderClient {
	tokenURL := d.tokenURL
	if tokenURL == "" {
		tokenURL = msLoginTokenURL(cb.AzureTenant)
	}
	apiBase := d.apiBase
	if apiBase == "" {
		apiBase = "https://api.securitycenter.microsoft.com"
	}
	return newDefenderClient(tokenURL, apiBase, d.scope, cb.ClientID, cb.ClientSecret, d.http)
}

// targetToMachine maps a SOAR step target to an MDE machine id. "machine:<id>" is used directly; anything
// else (optionally "host:<name>") is resolved by device DNS name.
func targetToMachine(ctx context.Context, c *defenderClient, target string) (string, error) {
	t := strings.TrimSpace(target)
	if id := strings.TrimPrefix(t, "machine:"); id != t {
		return strings.TrimSpace(id), nil
	}
	host := strings.TrimSpace(strings.TrimPrefix(t, "host:"))
	if host == "" {
		return "", fmt.Errorf("defender: empty target")
	}
	return c.resolveMachineID(ctx, host)
}

// mdeActionActive reports whether a machineAction status means the action is already in flight or done
// (so a re-issue would be redundant). Pending|InProgress|Succeeded; Failed/Cancelled/TimeOut are NOT active.
func mdeActionActive(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pending", "inprogress", "succeeded":
		return true
	}
	return false
}

// correlatorToken is the DELIMITED form of a correlator embedded in / matched against the MDE comment. The
// closing `]` makes it collision-free (`[nirvet:R:1]` is not a substring of `[nirvet:R:10]`) — round-#34 LOW.
func correlatorToken(correlator string) string { return "[nirvet:" + correlator + "]" }

// mdeComment builds the audit comment sent to MDE for the action. The correlator (run_id:step_index) is
// embedded as a delimited token so a later PreCheck (on this step or a crash-resume of it) can recognise OUR
// own action and keep it reversible, while a foreign isolation — carrying no/other correlator — stays
// non-reversible (H-1b).
func mdeComment(actionType string, params map[string]any, correlator string) string {
	c := "Nirvet SOAR " + actionType
	if r, ok := params["reverse_of"].(string); ok && r != "" {
		c += " (reverse of " + r + ")"
	}
	if correlator != "" {
		c += " " + correlatorToken(correlator)
	}
	return c
}
