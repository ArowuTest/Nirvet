package connector

// §6.11 D5 protected-identity guard — the Entra implementation of soar.ProtectedTargetGuard. Refuses (→ the
// supervisor withholds + escalates) a disable against a protected identity, three layers deep:
//   L1 static deny-list (protected_identities: break-glass / critical service accounts, per-tenant + global).
//   L2 dynamic Graph directory-role check (a static list misses people): the target holds a protected directory
//      role. This is a BLANKET withhold on protected-role membership — strictly stronger than a "last enabled
//      member of a protected role" check, so scoping the old all-roles last-of-role sweep to the protected set
//      (reviewer note) makes it fully subsumed by this check; we therefore no longer run a separate last-of-role
//      sweep (it only added over-escalation on trivial NON-protected roles the tenant never deemed protected).
//   L3 self-protection: never the identity Nirvet authenticates as (the connector client_id). Effectively vacuous
//      under app-only (client-credentials) auth — client_id is a service-principal appId, not a /users object, so
//      it won't match a real user disable — but retained as a cheap immutable invariant that also covers a future
//      delegated-auth mode where the connector could authenticate AS a user.
// A Graph error propagates up so the supervisor fails CLOSED. No-ops for non-entra connectors (vendor-aware seam).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// protectedConfigReader supplies the L1 deny-list + L2 protected-role names. soar.Repository satisfies it
// structurally (ProtectedIdentities / ProtectedRoles), so the guard needs no import of the soar repo.
type protectedConfigReader interface {
	ProtectedIdentities(ctx context.Context, tenantID uuid.UUID) ([]string, error)
	ProtectedRoles(ctx context.Context, tenantID uuid.UUID) ([]string, error)
}

// EntraProtectedGuard implements soar.ProtectedTargetGuard for identity actions. Endpoints injectable (tests);
// prod leaves them empty (per-tenant token URL, default Graph host, SafeClient).
type EntraProtectedGuard struct {
	cfg      protectedConfigReader
	tokenURL string
	apiBase  string
	scope    string
	http     *http.Client
}

// NewEntraProtectedGuard builds the guard. A non-empty apiBase MUST have passed ValidateGraphBaseURL.
func NewEntraProtectedGuard(cfg protectedConfigReader, tokenURL, apiBase, scope string, hc *http.Client) *EntraProtectedGuard {
	return &EntraProtectedGuard{cfg: cfg, tokenURL: tokenURL, apiBase: apiBase, scope: scope, http: hc}
}

func (g *EntraProtectedGuard) clientFor(cb Credentials) *entraClient {
	tokenURL := g.tokenURL
	if tokenURL == "" {
		tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", cb.AzureTenant)
	}
	apiBase := g.apiBase
	if apiBase == "" {
		apiBase = "https://graph.microsoft.com/v1.0"
	}
	return newEntraClient(tokenURL, apiBase, g.scope, cb.ClientID, cb.ClientSecret, g.http)
}

// CheckProtected implements soar.ProtectedTargetGuard.
func (g *EntraProtectedGuard) CheckProtected(ctx context.Context, tenantID uuid.UUID, connectorKey, actionKey, target string, creds []byte) (bool, string, error) {
	if !strings.EqualFold(connectorKey, string(KindEntraID)) {
		return false, "", nil // vendor-aware: this guard only covers identity actions (case-insensitive, H-1)
	}
	var cb Credentials
	if err := json.Unmarshal(creds, &cb); err != nil {
		return false, "", fmt.Errorf("entra guard: bad credentials bundle: %w", err)
	}
	ref := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(target), "user:"))
	if ref == "" {
		return false, "", fmt.Errorf("entra guard: empty target")
	}

	// L3 self (by target string, before any Graph call): never the identity Nirvet authenticates as.
	if cb.ClientID != "" && strings.EqualFold(ref, cb.ClientID) {
		return true, "self-protection: the identity Nirvet authenticates as", nil
	}

	deny, err := g.cfg.ProtectedIdentities(ctx, tenantID)
	if err != nil {
		return false, "", err
	}
	denySet := lowerSet(deny)
	if denySet[strings.ToLower(ref)] {
		return true, "on the protected-identity deny-list", nil
	}

	client := g.clientFor(cb)
	user, found, err := client.resolveUser(ctx, ref)
	if err != nil {
		return false, "", err // → supervisor fails closed
	}
	if !found {
		return false, "", nil // not our concern; the Actioner reports not-found
	}
	// Re-check L1/L3 against the resolved object id (target may have been a UPN).
	if denySet[strings.ToLower(user.ID)] {
		return true, "on the protected-identity deny-list", nil
	}
	if cb.ClientID != "" && strings.EqualFold(user.ID, cb.ClientID) {
		return true, "self-protection: the identity Nirvet authenticates as", nil
	}

	// L2 dynamic directory-role check: withhold if the target holds ANY protected directory role. This blanket
	// membership withhold is strictly stronger than a last-of-a-protected-role check, so (per reviewer note) we do
	// NOT run a separate all-roles last-of-role sweep — it only over-escalated on the last member of trivial
	// NON-protected roles the tenant never deemed protected. Protected roles are fully covered here regardless of
	// member count; the client keeps roleEnabledMemberCount for a possible future refined per-role policy.
	protRoles, err := g.cfg.ProtectedRoles(ctx, tenantID)
	if err != nil {
		return false, "", err
	}
	protSet := lowerSet(protRoles)
	roles, err := client.userDirectoryRoles(ctx, user.ID)
	if err != nil {
		return false, "", err // fail closed: can't verify roles → refuse
	}
	for _, role := range roles {
		if protSet[strings.ToLower(role.DisplayName)] {
			return true, "holds protected directory role: " + role.DisplayName, nil
		}
	}
	return false, "", nil
}

func lowerSet(in []string) map[string]bool {
	m := make(map[string]bool, len(in))
	for _, s := range in {
		m[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return m
}
