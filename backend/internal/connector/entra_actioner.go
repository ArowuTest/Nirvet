package connector

// §6.11 Entra vendor E-3 — the identity-containment Actioners (disable_user ⇄ enable_user). Attribution is
// TERMINAL-STATE (D2): a Graph user has no per-action correlator field, so PreCheck reads accountEnabled and a
// resume that finds the account already in the target state records changed=false — fail-SAFE (never re-does a
// state we cannot prove we caused; never wrongly re-enables a foreign disable). Synchronous PATCH (204=done) →
// Confirm is nil (D3): the reconciler confirms it on sight, no async poll. The D5 protected-identity guard runs
// at the supervisor seam BEFORE this Actioner, so a protected target never reaches here.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ArowuTest/nirvet/internal/soar"
)

// EntraActioner builds the Entra identity Actioners. Endpoints injectable (tests); prod leaves them empty
// (per-tenant token URL, default Graph host, netsafe.SafeClient).
type EntraActioner struct {
	tokenURL string
	apiBase  string
	scope    string
	http     *http.Client
}

// NewEntraActioner builds the factory. Empty endpoints select production defaults; nil http → SafeClient.
func NewEntraActioner(tokenURL, apiBase, scope string, hc *http.Client) *EntraActioner {
	return &EntraActioner{tokenURL: tokenURL, apiBase: apiBase, scope: scope, http: hc}
}

// Actioners returns the disable + enable Actioners. Action key `disable_user` matches the seeded catalog
// (connector_key entra-id); `enable_user` is the reverse, invoked by ReverseRun. Confirm is nil (synchronous).
func (d *EntraActioner) Actioners() []soar.Actioner {
	return []soar.Actioner{
		{
			ConnectorKey: string(KindEntraID), Action: "disable_user",
			PreCheck: true, Reversible: true, Inverse: "enable_user",
			Fn: func(ctx context.Context, creds []byte, target string, params map[string]any) (string, map[string]any, error) {
				return d.act(ctx, creds, target, false)
			},
		},
		{
			ConnectorKey: string(KindEntraID), Action: "enable_user",
			PreCheck: true, Reversible: true, Inverse: "disable_user",
			Fn: func(ctx context.Context, creds []byte, target string, params map[string]any) (string, map[string]any, error) {
				return d.act(ctx, creds, target, true)
			},
		},
	}
}

// act sets accountEnabled to `want`. Terminal-state PreCheck (fail-SAFE): if already at `want`, no PATCH and
// changed=false. prior_state.action_id carries the user id (the reconciler treats Confirm=nil as confirmed).
func (d *EntraActioner) act(ctx context.Context, creds []byte, target string, want bool) (string, map[string]any, error) {
	var cb Credentials
	if err := json.Unmarshal(creds, &cb); err != nil {
		return "", nil, fmt.Errorf("entra: bad credentials bundle: %w", err)
	}
	client := d.clientFor(cb)
	ref := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(target), "user:"))
	user, found, err := client.resolveUser(ctx, ref)
	if err != nil {
		return "", nil, err
	}
	if !found {
		return "", nil, fmt.Errorf("entra: no user %q", ref)
	}
	if user.AccountEnabled == want {
		// Already in the target state (a foreign/prior change, or a crash-resume finding our own effect): no
		// PATCH, changed=false → reverse never re-does it. This is the D2 fail-SAFE resolution of ambiguity.
		return "already:" + user.ID,
			map[string]any{"changed": false, "user_id": user.ID, "account_enabled": user.AccountEnabled, "action_id": user.ID}, nil
	}
	if err := client.setAccountEnabled(ctx, user.ID, want); err != nil {
		return "", map[string]any{"changed": false, "user_id": user.ID}, err
	}
	return user.ID, map[string]any{"changed": true, "user_id": user.ID, "action_id": user.ID}, nil
}

func (d *EntraActioner) clientFor(cb Credentials) *entraClient {
	tokenURL := d.tokenURL
	if tokenURL == "" {
		tokenURL = msLoginTokenURL(cb.AzureTenant)
	}
	apiBase := d.apiBase
	if apiBase == "" {
		apiBase = "https://graph.microsoft.com/v1.0"
	}
	return newEntraClient(tokenURL, apiBase, d.scope, cb.ClientID, cb.ClientSecret, d.http)
}
