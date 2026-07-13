package database

// Runtime RLS-constrained-role guard (fail-closed backstop for tenant isolation).
//
// The owner_bypass policy (migration 0118) lets the DB OWNER through every RLS table so migrations + SECURITY
// DEFINER functions work on managed Postgres (where the owner is a non-superuser). That makes tenant isolation
// depend on the API connecting as the non-owner nirvet_app role. If NIRVET_DATABASE_URL is ever misconfigured to
// the owner — or a superuser / BYPASSRLS role — owner_bypass (or the bypass attribute) fires for EVERY query,
// silently disabling cross-tenant isolation with nothing to catch it. AssertRLSConstrainedRole is the startup
// assertion: a misconfigured runtime DSN crashes loudly instead of serving with isolation off. It complements
// schemacheck (which asserts owner_bypass exists on every RLS table — the schema side) with the runtime side.

import (
	"context"
	"fmt"
)

// AssertRLSConstrainedRole returns an error if the current runtime connection role can bypass Row-Level Security
// by ANY of three vectors: superuser, the BYPASSRLS attribute, or OWNING an RLS-enabled table (the owner_bypass
// path — on managed Postgres the owner is a non-superuser, so the rolsuper/rolbypassrls check alone would miss
// it; the tableowner check is the important addition). Fails CLOSED: a query error is treated as an unverifiable,
// and therefore unsafe, role. cmd/api calls this at boot; cmd/migrate MUST NOT (it legitimately connects as the
// owner and expects the bypass).
func (db *DB) AssertRLSConstrainedRole(ctx context.Context) error {
	var role string
	var unconstrained bool
	err := db.Pool.QueryRow(ctx, `
		SELECT current_user,
		  COALESCE((SELECT bool_or(rolsuper OR rolbypassrls)
		            FROM pg_roles WHERE rolname = current_user), false)
		  OR EXISTS (SELECT 1 FROM pg_tables
		             WHERE schemaname = 'public' AND rowsecurity
		               AND tableowner = current_user)`).Scan(&role, &unconstrained)
	if err != nil {
		return fmt.Errorf("cannot verify the runtime DB role is RLS-constrained (treating as unsafe): %w", err)
	}
	if unconstrained {
		return fmt.Errorf("runtime DB role %q can bypass RLS (superuser/BYPASSRLS or owns RLS tables); the API "+
			"must connect as the non-owner nirvet_app role — check NIRVET_DATABASE_URL", role)
	}
	return nil
}
