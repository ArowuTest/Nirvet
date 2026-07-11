package connector

// §6.11 D5 protected-target guard — the HOST (Defender isolate) implementation of soar.ProtectedTargetGuard,
// the sibling of EntraProtectedGuard for identity actions (M3). It refuses (→ the supervisor withholds +
// escalates) an isolate_endpoint against a crown-jewel host the tenant has designated in protected_hosts. Pure
// config match (a case-insensitive substring), no vendor call — so it only fails closed on a DB read error, and
// no-ops for any connector/action that is not Defender isolate (vendor-aware seam).

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// protectedHostsReader supplies the per-tenant + global protected-host patterns. soar.Repository satisfies it
// structurally (ProtectedHosts), so the guard needs no import of the soar repo.
type protectedHostsReader interface {
	ProtectedHosts(ctx context.Context, tenantID uuid.UUID) ([]string, error)
}

// HostProtectedGuard implements soar.ProtectedTargetGuard for Defender host isolation.
type HostProtectedGuard struct{ cfg protectedHostsReader }

// NewHostProtectedGuard builds the host guard.
func NewHostProtectedGuard(cfg protectedHostsReader) *HostProtectedGuard { return &HostProtectedGuard{cfg: cfg} }

// CheckProtected withholds an isolate_endpoint whose target matches a protected-host pattern.
func (g *HostProtectedGuard) CheckProtected(ctx context.Context, tenantID uuid.UUID, connectorKey, actionKey, target string, _ []byte) (bool, string, error) {
	// Vendor-aware: only Defender host ISOLATION is gated here (release_endpoint is the reversible undo).
	// Case-INSENSITIVE (H-1): the actioner registry matches connector/action case-insensitively, so a
	// mis-cased catalog override ("Defender") must not slip past this guard while still firing the actioner.
	if !strings.EqualFold(connectorKey, string(KindDefender)) || !strings.EqualFold(actionKey, "isolate_endpoint") {
		return false, "", nil
	}
	patterns, err := g.cfg.ProtectedHosts(ctx, tenantID)
	if err != nil {
		return false, "", err // → supervisor fails CLOSED (cannot verify blast radius → refuse)
	}
	ref := strings.ToLower(strings.TrimSpace(target))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p != "" && strings.Contains(ref, p) {
			return true, "crown-jewel host: matches protected-host pattern " + p, nil
		}
	}
	return false, "", nil
}
