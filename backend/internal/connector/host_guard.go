package connector

// §6.11 D5 protected-target guard — the HOST (Defender isolate) implementation of soar.ProtectedTargetGuard, the
// sibling of EntraProtectedGuard for identity actions (M3). It refuses (→ the supervisor withholds + escalates)
// an isolate_endpoint against a crown-jewel host the tenant designated in protected_hosts.
//
// It matches on the CANONICAL machine identity the actioner will act on — not the raw target string. A cheap
// substring pass covers hostname/FQDN targets with no vendor call; if that doesn't match, the guard resolves the
// target to the same machine the actioner would (machine:<id> → id; else name → id) and re-checks the protected
// patterns against the machine's canonical computerDnsName and id. This closes the id-vs-name bypass: a host
// protected by name can no longer be isolated by targeting `machine:<its-device-id>`, which the raw-string match
// could not see. Mirrors EntraProtectedGuard, which re-checks the deny-list against the resolved object id.
// Fails CLOSED: a config-read error, or an unresolvable target while crown-jewels exist, → the guard withholds.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// protectedHostsReader supplies the per-tenant + global protected-host patterns. soar.Repository satisfies it
// structurally (ProtectedHosts), so the guard needs no import of the soar repo.
type protectedHostsReader interface {
	ProtectedHosts(ctx context.Context, tenantID uuid.UUID) ([]string, error)
}

// HostProtectedGuard implements soar.ProtectedTargetGuard for Defender host isolation. Endpoints are injectable
// (tests); prod leaves them empty (per-tenant token URL, default MDE host, SafeClient).
type HostProtectedGuard struct {
	cfg      protectedHostsReader
	tokenURL string
	apiBase  string
	scope    string
	http     *http.Client
}

// NewHostProtectedGuard builds the host guard.
func NewHostProtectedGuard(cfg protectedHostsReader, tokenURL, apiBase, scope string, hc *http.Client) *HostProtectedGuard {
	return &HostProtectedGuard{cfg: cfg, tokenURL: tokenURL, apiBase: apiBase, scope: scope, http: hc}
}

func (g *HostProtectedGuard) clientFor(cb Credentials) *defenderClient {
	tokenURL := g.tokenURL
	if tokenURL == "" {
		tokenURL = msLoginTokenURL(cb.AzureTenant)
	}
	apiBase := g.apiBase
	if apiBase == "" {
		apiBase = "https://api.securitycenter.microsoft.com"
	}
	return newDefenderClient(tokenURL, apiBase, g.scope, cb.ClientID, cb.ClientSecret, g.http)
}

// CheckProtected withholds an isolate_endpoint whose target resolves to a protected host.
func (g *HostProtectedGuard) CheckProtected(ctx context.Context, tenantID uuid.UUID, connectorKey, actionKey, target string, creds []byte) (bool, string, error) {
	// Vendor-aware: only Defender host ISOLATION is gated here (release_endpoint is the reversible undo).
	// Case-INSENSITIVE (H-1): the actioner registry matches connector/action case-insensitively, so a mis-cased
	// catalog override ("Defender") must not slip past this guard while still firing the actioner.
	if !strings.EqualFold(connectorKey, string(KindDefender)) || !strings.EqualFold(actionKey, "isolate_endpoint") {
		return false, "", nil
	}
	patterns, err := g.cfg.ProtectedHosts(ctx, tenantID)
	if err != nil {
		return false, "", err // → supervisor fails CLOSED (cannot verify blast radius → refuse)
	}
	if len(patterns) == 0 {
		return false, "", nil // nothing designated protected → nothing to resolve, allow
	}

	// 1) Cheap match on the RAW target — covers hostname/FQDN targets with no vendor call (preserves behaviour).
	ref := strings.ToLower(strings.TrimSpace(target))
	for _, p := range patterns {
		if pp := strings.ToLower(strings.TrimSpace(p)); pp != "" && strings.Contains(ref, pp) {
			return true, "crown-jewel host: matches protected-host pattern " + strings.TrimSpace(p), nil
		}
	}

	// 2) The raw target didn't match. Resolve it to the CANONICAL machine identity the actioner will act on and
	// re-check — this is what closes the machine:<id> (and alias) bypass. Resolution needs creds; without them the
	// action itself can't fire (the actioner needs the same creds), so raw-only matching is safe in that case.
	if len(creds) == 0 {
		return false, "", nil
	}
	var cb Credentials
	if err := json.Unmarshal(creds, &cb); err != nil {
		return false, "", fmt.Errorf("host guard: bad credentials bundle: %w", err)
	}
	id, dns, err := resolveCanonicalMachine(ctx, g.clientFor(cb), target)
	if err != nil {
		// Crown-jewels ARE configured and we cannot verify this target isn't one of them → fail closed (withhold
		// + escalate), consistent with the config-read error path above.
		return false, "", fmt.Errorf("host guard: cannot resolve target to verify blast radius: %w", err)
	}
	idL, dnsL := strings.ToLower(id), strings.ToLower(dns)
	for _, p := range patterns {
		pp := strings.ToLower(strings.TrimSpace(p))
		if pp == "" {
			continue
		}
		if strings.Contains(dnsL, pp) || (idL != "" && strings.Contains(idL, pp)) {
			return true, "crown-jewel host (target resolves to " + dns + "): matches protected-host pattern " + strings.TrimSpace(p), nil
		}
	}
	return false, "", nil
}

// resolveCanonicalMachine maps a SOAR target to the machine id + canonical computerDnsName the actioner will act
// on. "machine:<id>" uses the id directly; anything else (optionally "host:<name>") resolves the name to an id.
// Both then fetch the canonical DNS name, so name-pattern matching sees the real host — not the caller's chosen id.
func resolveCanonicalMachine(ctx context.Context, c *defenderClient, target string) (id, dns string, err error) {
	t := strings.TrimSpace(target)
	if rest := strings.TrimPrefix(t, "machine:"); rest != t {
		id = strings.TrimSpace(rest)
		dns, err = c.machineDNSName(ctx, id)
		return id, dns, err
	}
	host := strings.TrimSpace(strings.TrimPrefix(t, "host:"))
	if host == "" {
		return "", "", fmt.Errorf("empty target")
	}
	if id, err = c.resolveMachineID(ctx, host); err != nil {
		return "", "", err
	}
	dns, err = c.machineDNSName(ctx, id)
	return id, dns, err
}
