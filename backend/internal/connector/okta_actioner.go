package connector

// §6.11 G1 — Okta identity-containment Actioners (first NON-Microsoft response vendor). Mirrors the Entra
// terminal-state (D2) fail-safe, generalized across Okta's MULTI-VALUED `status` (Entra's accountEnabled is a
// clean boolean; Okta's status has ~7 values). PreCheck reads status; a transition is only issued from the
// expected state, and any already-access-denied state resolves to changed=false GOAL-MET (no call, no 400) so a
// containment on an already-suspended/deprovisioned account never errors or double-acts. Synchronous lifecycle
// (200) → Confirm nil (the reconciler confirms on sight). The D5 protected-identity guard runs at the supervisor
// seam BEFORE this Actioner. Action keys are vendor-prefixed (okta_*) because the action catalog is keyed by
// action_key alone with a routing connector_key column — a bare `revoke_sessions` would collide with Entra's.
//
// Reviewer must-adds (RESPONSE_ACTIONER_OKTA_GATE.md §8), all implemented here:
//   MA-1: okta_revoke_sessions declares Idempotent:true (else canAutoRun refuses it — actioner.go:96-98).
//   MA-2: every Fn sets priorState["action_id"] to the BARE Okta user id (the reconciler's poll key, never prefixed).
//   MA-3: the multi-state fail-safe map below (already-access-denied → goal-met; STAGED/PROVISIONED → not-applicable).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ArowuTest/nirvet/internal/soar"
)

// oktaAccessDenied are Okta statuses in which a user already cannot authenticate — so a suspend's containment goal
// is ALREADY met. Suspending from these would 400; instead we record changed=false (D2 fail-safe), never erroring
// and never re-acting. (SUSPENDED is our own effect or a foreign one; either way the goal holds and reverse must
// only undo a state we can prove we caused via changed=true — which we never set here.)
var oktaAccessDenied = map[string]bool{
	"SUSPENDED":        true,
	"DEPROVISIONED":    true,
	"LOCKED_OUT":       true,
	"PASSWORD_EXPIRED": true,
}

// OktaActioner builds the Okta identity Actioners. Endpoints injectable for tests; prod leaves them empty so the
// per-tenant org URL + SSWS token come from the vault-decrypted Credentials bundle, and http nil → SafeClient.
type OktaActioner struct {
	orgURL string
	token  string
	http   *http.Client
}

// NewOktaActioner builds the factory. Empty orgURL/token ⇒ read them per-call from the tenant credentials bundle.
func NewOktaActioner(orgURL, token string, hc *http.Client) *OktaActioner {
	return &OktaActioner{orgURL: orgURL, token: token, http: hc}
}

// Actioners returns suspend/unsuspend (reversible identity containment) + revoke_sessions (idempotent, one-way).
func (a *OktaActioner) Actioners() []soar.Actioner {
	return []soar.Actioner{
		{
			ConnectorKey: string(KindOkta), Action: "okta_suspend_user",
			PreCheck: true, Reversible: true, Inverse: "okta_unsuspend_user",
			Fn: func(ctx context.Context, creds []byte, target string, _ map[string]any) (string, map[string]any, error) {
				return a.setSuspended(ctx, creds, target, true)
			},
		},
		{
			ConnectorKey: string(KindOkta), Action: "okta_unsuspend_user",
			PreCheck: true, Reversible: true, Inverse: "okta_suspend_user",
			Fn: func(ctx context.Context, creds []byte, target string, _ map[string]any) (string, map[string]any, error) {
				return a.setSuspended(ctx, creds, target, false)
			},
		},
		{
			// MA-1: Idempotent (revoking sessions twice is harmless) — required for canAutoRun. One-way (no undo).
			ConnectorKey: string(KindOkta), Action: "okta_revoke_sessions",
			Idempotent: true,
			Fn: func(ctx context.Context, creds []byte, target string, _ map[string]any) (string, map[string]any, error) {
				return a.revoke(ctx, creds, target)
			},
		},
	}
}

// setSuspended suspends (want=true) or unsuspends (want=false) with the multi-state terminal fail-safe (MA-3).
func (a *OktaActioner) setSuspended(ctx context.Context, creds []byte, target string, want bool) (string, map[string]any, error) {
	client, ref, err := a.clientFor(creds, target)
	if err != nil {
		return "", nil, err
	}
	u, found, err := client.resolveUser(ctx, ref)
	if err != nil {
		return "", nil, err
	}
	if !found {
		return "", nil, fmt.Errorf("okta: no user %q", ref)
	}
	if want { // SUSPEND
		if oktaAccessDenied[u.Status] {
			// Already access-denied → containment goal met. No call, changed=false (D2 fail-safe).
			return "already:" + u.ID, goalMet(u), nil
		}
		if u.Status != "ACTIVE" {
			// STAGED / PROVISIONED (never activated) — no active sessions to contain, and suspend would 400.
			// Treat as goal-met/not-applicable: no call, no error. Documented choice (OQ#4).
			return "inapplicable:" + u.ID, goalMet(u), nil
		}
		if err := client.lifecycle(ctx, u.ID, "suspend"); err != nil {
			return "", map[string]any{"changed": false, "user_id": u.ID}, err
		}
		return u.ID, changed(u.ID), nil
	}
	// UNSUSPEND (the reverse) — valid ONLY from SUSPENDED. Never resurrect a DEPROVISIONED/other-state account.
	if u.Status != "SUSPENDED" {
		return "already:" + u.ID, goalMet(u), nil
	}
	if err := client.lifecycle(ctx, u.ID, "unsuspend"); err != nil {
		return "", map[string]any{"changed": false, "user_id": u.ID}, err
	}
	return u.ID, changed(u.ID), nil
}

// revoke clears the user's sessions. Idempotent; no prior-state to preserve beyond the id.
func (a *OktaActioner) revoke(ctx context.Context, creds []byte, target string) (string, map[string]any, error) {
	client, ref, err := a.clientFor(creds, target)
	if err != nil {
		return "", nil, err
	}
	u, found, err := client.resolveUser(ctx, ref)
	if err != nil {
		return "", nil, err
	}
	if !found {
		return "", nil, fmt.Errorf("okta: no user %q", ref)
	}
	if err := client.revokeSessions(ctx, u.ID); err != nil {
		return "", map[string]any{"changed": false, "user_id": u.ID}, err
	}
	return u.ID, changed(u.ID), nil
}

// clientFor builds the per-call client from the actioner defaults or the vault credentials, and normalizes the
// target ref (strips a "user:" prefix).
func (a *OktaActioner) clientFor(creds []byte, target string) (*oktaClient, string, error) {
	var cb Credentials
	if err := json.Unmarshal(creds, &cb); err != nil {
		return nil, "", fmt.Errorf("okta: bad credentials bundle: %w", err)
	}
	orgURL := a.orgURL
	if orgURL == "" {
		orgURL = cb.OktaOrgURL
	}
	token := a.token
	if token == "" {
		token = cb.OktaToken
	}
	if orgURL == "" || token == "" {
		return nil, "", fmt.Errorf("okta: missing org URL or API token in credentials")
	}
	ref := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(target), "user:"))
	return newOktaClient(orgURL, token, a.http), ref, nil
}

// goalMet/changed build the priorState maps. BOTH set action_id to the BARE user id (MA-2) — the reconciler's
// poll key. goalMet records changed=false (no effect we caused); changed records changed=true (we transitioned).
func goalMet(u oktaUser) map[string]any {
	return map[string]any{"changed": false, "user_id": u.ID, "status": u.Status, "action_id": u.ID}
}
func changed(userID string) map[string]any {
	return map[string]any{"changed": true, "user_id": userID, "action_id": userID}
}
