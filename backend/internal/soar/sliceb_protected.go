package soar

// §6.11 D5 protected-target guard (blast-radius containment) — the supervisor seam + config readers. A destructive
// identity/host action against a protected target (last Global-Admin, break-glass, a crown-jewel host, or the
// identity Nirvet authenticates as) is the SELF-SEALING failure: it can lock the tenant out INCLUDING the ability
// to undo it. So the supervisor consults the guard AFTER decrypting creds and BEFORE the Actioner call; a protected
// target → WITHHELD + human escalation (awaiting_customer) + audit + HIGH alert, never a silent effect. A guard
// ERROR fails CLOSED (withhold) — when we cannot verify the blast radius, we refuse.

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ProtectedTargetGuard is consulted before a destructive connector step. Vendor-aware: it no-ops for connectors it
// does not guard. Returns protected + a human-readable reason, or an error (→ the supervisor fails closed).
type ProtectedTargetGuard interface {
	CheckProtected(ctx context.Context, tenantID uuid.UUID, connectorKey, actionKey, target string, creds []byte) (protected bool, reason string, err error)
}

// WithGuard APPENDS a protected-target guard to the chain (identity, host, …) — call it once per guard.
// Every guard in the chain is consulted before a destructive action; any one may withhold. Returns the
// supervisor for chaining.
func (s *Supervisor) WithGuard(g ProtectedTargetGuard) *Supervisor { s.guards = append(s.guards, g); return s }

// ProtectedIdentities returns the tenant's own + global protected identity refs (lower-cased) — the L1 deny-list.
func (r *Repository) ProtectedIdentities(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	return r.protectedList(ctx, tenantID, `SELECT lower(identity_ref) FROM protected_identities`)
}

// ProtectedRoles returns the tenant's own + global protected directory-role names (lower-cased) — L2.
func (r *Repository) ProtectedRoles(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	return r.protectedList(ctx, tenantID, `SELECT lower(role_name) FROM protected_directory_roles`)
}

// ProtectedHosts returns the tenant's own + global protected-host patterns (lower-cased) — the host-isolation
// blast-radius net (M3), matched as case-insensitive substrings against an isolate target.
func (r *Repository) ProtectedHosts(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	return r.protectedList(ctx, tenantID, `SELECT lower(pattern) FROM protected_hosts`)
}

func (r *Repository) protectedList(ctx context.Context, tenantID uuid.UUID, q string) ([]string, error) {
	var out []string
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, q)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if e := rows.Scan(&s); e != nil {
				return e
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}
