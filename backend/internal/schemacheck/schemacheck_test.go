// Package schemacheck holds structural schema-invariant tests that run against the migrated database
// (gated on NIRVET_TEST_DATABASE_URL, so they execute in the same CI step as the integration tests).
//
// These are the second and third of the three structural guards the reviewer put at the top of the
// hardening backlog (the first is scripts/check-outbound-http.sh). They retire, at CI time, two classes
// of "a control applied everywhere except one sibling" bug that recurred across review rounds:
//   - a UNIQUE/PK on a tenant table that omits tenant_id → cross-tenant collision (R5-H3 stix_objects);
//   - a Go enum drifting from its column's CHECK constraint → an insert that fails at runtime, or a dead
//     DB value the code never emits.
//
// They query the live catalog, so they cannot be fooled by SQL formatting the way a text grep could.
package schemacheck_test

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/ai"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
)

func connect(t *testing.T) *database.DB {
	t.Helper()
	dsn := testsupport.RequireDSN(t)
	db, err := database.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// TestTenantCompositeConstraints (guard #2): every PK/UNIQUE on a table that has a tenant_id column must
// include tenant_id — UNLESS the constraint is already globally unique by construction (it contains a
// uuid column, e.g. a surrogate row id or a uuid FK), or it is an explicitly-waived global pre-tenant
// lookup key. A natural-key UNIQUE that omits tenant_id lets two tenants collide (R5-H3).
func TestTenantCompositeConstraints(t *testing.T) {
	db := connect(t)

	// Waivers: constraints that INTENTIONALLY omit tenant_id because the value is looked up BEFORE a
	// tenant context exists (the lookup resolves the tenant), so it must be globally unique.
	waived := map[string]string{
		"api_keys_prefix_key":                  "api-key prefix is a global pre-tenant lookup (auth resolves the tenant from the key)",
		"user_invitations_token_hash_key":      "invite token hash is a global pre-tenant lookup (validated before any tenant context)",
		"password_reset_tokens_token_hash_key": "reset token hash is a global pre-tenant lookup (the token resolves the tenant; validated before any tenant context)",
		"refresh_tokens_token_hash_key":        "refresh token hash is a global pre-tenant lookup (the /auth/refresh cookie resolves the tenant via the SD function; validated before any tenant context) — ADR-0007",
		"approval_link_token_hash_key":         "customer-approval single-use link token hash is a global pre-tenant lookup (consume_approval_link resolves the tenant from the hash; validated before any tenant context) — #188 customer-approval",
	}

	// A constraint is "already globally unique by construction" (so it needn't include tenant_id) when it
	// contains a uuid column, OR it is a single-column key on a SURROGATE — a DB-generated column (has a
	// default like gen_random_uuid()/nextval, or is a GENERATED ... AS IDENTITY column). A single-column
	// key on a NATURAL, caller-supplied value (no default, no identity — e.g. a STIX id text) is exactly
	// the collision risk we want to catch, so it is NOT excluded.
	rows, err := db.Pool.Query(context.Background(), `
		SELECT c.conrelid::regclass::text AS tbl, c.conname
		FROM pg_constraint c
		JOIN pg_attribute ta ON ta.attrelid = c.conrelid AND ta.attname = 'tenant_id' AND NOT ta.attisdropped
		WHERE c.contype IN ('p','u')
		  AND c.connamespace = 'public'::regnamespace
		  AND NOT (ta.attnum = ANY(c.conkey))                 -- constraint omits tenant_id
		  AND NOT EXISTS (                                    -- contains a uuid column → globally unique
		    SELECT 1 FROM unnest(c.conkey) k
		    JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k
		    JOIN pg_type ty ON ty.oid = a.atttypid
		    WHERE ty.typname = 'uuid'
		  )
		  AND NOT (                                           -- single-column surrogate (default or identity)
		    array_length(c.conkey,1) = 1
		    AND EXISTS (
		      SELECT 1 FROM pg_attribute a
		      WHERE a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
		        AND (a.atthasdef OR a.attidentity <> '')
		    )
		  )
		ORDER BY 1, 2`)
	if err != nil {
		t.Fatalf("catalog query: %v", err)
	}
	defer rows.Close()

	var offenders []string
	for rows.Next() {
		var tbl, conname string
		if err := rows.Scan(&tbl, &conname); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if _, ok := waived[conname]; ok {
			continue
		}
		offenders = append(offenders, tbl+"."+conname)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("PK/UNIQUE on a tenant table omits tenant_id (cross-tenant collision risk) — make it "+
			"composite, or add an explicit waiver if it is a global pre-tenant lookup key: %v", offenders)
	}
}

// TestTenantForceRLS (guard #4, reviewer P2-1): every table carrying a tenant_id column must have FORCE
// ROW LEVEL SECURITY plus policy coverage for BOTH read (a USING clause) and write (a WITH CHECK clause) —
// the platform's #1 isolation invariant, now regression-guarded in CI rather than by a one-time review. A
// future tenant-data table that ships with a tenant_id column and no RLS fails the build. The ONLY
// exceptions are three system/platform tables that carry tenant_id as routing/attribution metadata and
// have no tenant-context (WithTenant) read path — each explicitly allowlisted with a justification, exactly
// as the composite-constraint waiver does. USING+WITH_CHECK coverage may come from one ALL policy (the
// canonical tenant_isolation) or from a set of policies; we require the set to provide both.
func TestTenantForceRLS(t *testing.T) {
	db := connect(t)

	// System tables that carry tenant_id but are NOT tenant-owned content and have no tenant-facing reader
	// (verified in pass 2): each is touched only at pool level, under WithSystem, or via padmin CRUD, so
	// FORCE-RLS would break it (no tenant GUC → zero rows). Every future exception must be added here with a
	// justification — that IS the control.
	allowed := map[string]string{
		"ingest_jobs":        "internal work queue drained at pool level by the worker across ALL tenants (never WithTenant); tenant_id is routing metadata",
		"syslog_sources":     "cert-fingerprint→tenant attribution registry, read under WithSystem at connection-accept BEFORE any tenant context exists (the lookup discovers the tenant); padmin CRUD only",
		"tenant_offboarding": "offboard-evidence record deliberately retained through the purge; padmin-managed; no tenant-facing reader",
	}

	// One row per tenant_id table: does it FORCE RLS, and do its policies (if any) collectively provide a
	// USING clause and a WITH CHECK clause? LEFT JOIN so a table with zero policies yields has_using=has_check=false.
	rows, err := db.Pool.Query(context.Background(), `
		SELECT c.relname,
		       c.relforcerowsecurity,
		       COALESCE(bool_or(p.qual IS NOT NULL), false)       AS has_using,
		       COALESCE(bool_or(p.with_check IS NOT NULL), false) AS has_check
		FROM pg_class c
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
		LEFT JOIN pg_policies p ON p.schemaname = 'public' AND p.tablename = c.relname
		WHERE c.relkind = 'r' AND c.relnamespace = 'public'::regnamespace
		GROUP BY c.relname, c.relforcerowsecurity
		ORDER BY c.relname`)
	if err != nil {
		t.Fatalf("catalog query: %v", err)
	}
	defer rows.Close()

	var offenders []string
	for rows.Next() {
		var tbl string
		var force, hasUsing, hasCheck bool
		if err := rows.Scan(&tbl, &force, &hasUsing, &hasCheck); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if _, ok := allowed[tbl]; ok {
			continue
		}
		if !force || !hasUsing || !hasCheck {
			offenders = append(offenders, fmt.Sprintf("%s(force=%v using=%v check=%v)", tbl, force, hasUsing, hasCheck))
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("tenant_id table missing FORCE-RLS + USING+WITH_CHECK policy coverage (the #1 tenant-isolation "+
			"invariant) — add the tenant_isolation policy, or add a justified allowlist entry if it is a system "+
			"table: %v", offenders)
	}
}

// checkValueRe pulls the quoted literals out of a CHECK constraint definition, e.g.
// CHECK ((stage = ANY (ARRAY['draft'::text, 'qa'::text]))) -> [draft qa].
var checkValueRe = regexp.MustCompile(`'([^']*)'`)

// enumRegistry maps a column to the Go value set that is its source of truth. Importing the consts
// (detection/auth/tenant) makes those un-driftable; the cross-cutting sets (severity, SOAR risk class)
// have no single Go home, so they are listed with their source noted. Adding a new enum'd column means
// adding it here — that IS the enforcement.
func enumRegistry() map[string][]string {
	sev := []string{"informational", "low", "medium", "high", "critical"} // canonical severity (SRS §10.2 P1-P5)
	return map[string][]string{
		"detection_rules.stage": {
			detection.StageDraft, detection.StagePeerReview, detection.StageQA, detection.StagePilot,
			detection.StageProduction, detection.StageTuned, detection.StageRetired,
		},
		"detection_feedback.disposition": {
			string(detection.DispTruePositive), string(detection.DispFalsePositive),
			string(detection.DispBenign), string(detection.DispDuplicate),
		},
		"users.role": {
			string(auth.RolePlatformAdmin), string(auth.RoleSOCManager), string(auth.RoleAnalystT1),
			string(auth.RoleAnalystT2), string(auth.RoleAnalystT3), string(auth.RoleDetectionEng),
			string(auth.RoleCustomerAdmin), string(auth.RoleCustomerViewer),
		},
		"tenants.service_tier": {
			string(tenant.TierEssential), string(tenant.TierStandard), string(tenant.TierAdvanced),
			string(tenant.TierCritical), string(tenant.TierEnterprise),
		},
		"tenants.isolation_tier": {
			string(tenant.IsolationPooled), string(tenant.IsolationDedicated), string(tenant.IsolationSovereign),
		},
		"detection_rules.severity": sev,
		"events.severity":          sev,
		"alerts.severity":          sev,
		"incidents.severity":       sev,
		// SOAR §9.5 risk classes (source: reference-nirvet-srs-spine / soar_action_catalog seed).
		"soar_action_catalog.risk_class": {"informational", "low", "medium", "high", "business_critical"},
		// §6.12 #117 admin-configurable AI providers.
		"ai_provider.provider_kind":           {string(ai.KindAnthropic), string(ai.KindOpenAICompatible), string(ai.KindDisabled)},
		"ai_provider_allowed_endpoint.scheme": {string(ai.SchemeHTTP), string(ai.SchemeHTTPS)},
	}
}

// TestEnumCheckConsistency (guard #3): each registered column's CHECK-constraint value set must exactly
// equal its Go source-of-truth set. Catches drift in BOTH directions.
func TestEnumCheckConsistency(t *testing.T) {
	db := connect(t)
	for col, want := range enumRegistry() {
		parts := strings.SplitN(col, ".", 2)
		tbl, column := parts[0], parts[1]
		var def string
		err := db.Pool.QueryRow(context.Background(), `
			SELECT pg_get_constraintdef(c.oid)
			FROM pg_constraint c
			JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
			WHERE c.contype = 'c' AND c.conrelid = $1::regclass AND a.attname = $2
			  AND array_length(c.conkey,1) = 1`, tbl, column).Scan(&def)
		if err != nil {
			t.Errorf("%s: no single-column CHECK found (%v)", col, err)
			continue
		}
		got := map[string]bool{}
		for _, m := range checkValueRe.FindAllStringSubmatch(def, -1) {
			got[m[1]] = true
		}
		wantSet := map[string]bool{}
		for _, v := range want {
			wantSet[v] = true
		}
		if !equalSets(got, wantSet) {
			t.Errorf("%s: CHECK values %v drift from Go source-of-truth %v", col, keys(got), keys(wantSet))
		}
	}
}

func equalSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestPolicyGrantParity (guard #4): every per-command RLS policy on a public table must be backed by
// the matching table GRANT to the application role nirvet_app. RLS decides which ROWS are visible; the
// GRANT decides whether the role may touch the table at all. A FOR SELECT/INSERT/UPDATE/DELETE policy
// with no matching grant is a latent "permission denied" at runtime — and it hides in local/CI because
// migrations and superuser-owner tests bypass both grants and RLS. This retires exactly the class that
// shipped in 0066/0098 (protected_hosts had four policies and zero grants; protected_identities /
// protected_directory_roles had an UPDATE policy but no UPDATE grant), fixed in 0117.
//
// Only explicit per-command policies are checked. A no-FOR (ALL) policy reports cmd='ALL' and cannot be
// mapped to a single privilege without false-positiving on intentionally-immutable tables (which carry
// a broad policy but deliberately withhold UPDATE/DELETE grants), so those are out of scope here.
func TestPolicyGrantParity(t *testing.T) {
	db := connect(t)

	rows, err := db.Pool.Query(context.Background(), `
		SELECT p.tablename, p.cmd
		FROM pg_policies p
		WHERE p.schemaname = 'public'
		  AND p.cmd IN ('SELECT','INSERT','UPDATE','DELETE')
		  AND NOT has_table_privilege('nirvet_app', ('public.'||quote_ident(p.tablename))::regclass, p.cmd)
		ORDER BY p.tablename, p.cmd`)
	if err != nil {
		t.Fatalf("policy/grant parity query: %v", err)
	}
	defer rows.Close()

	var offenders []string
	for rows.Next() {
		var tbl, cmd string
		if err := rows.Scan(&tbl, &cmd); err != nil {
			t.Fatalf("scan: %v", err)
		}
		offenders = append(offenders, fmt.Sprintf("%s missing %s grant", tbl, cmd))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("RLS policy without matching nirvet_app GRANT (the app would fail with 'permission denied' "+
			"at runtime — add the GRANT to the migration that creates the policy): %v", offenders)
	}
}

// TestOwnerBypassPolicy (guard #5): every RLS-enabled public table must carry the `owner_bypass` policy
// (migration 0118). The platform's SECURITY DEFINER functions (auth lookups, background reapers,
// cross-tenant fleet reads) run as the DB owner and must bypass RLS. Locally the owner is a superuser and
// bypasses natively; on managed Postgres the owner is NOT a superuser, so FORCE ROW LEVEL SECURITY binds
// it and every one of those functions silently returns zero rows (no login, no async processing). The
// owner_bypass policy restores the owner's exemption without weakening nirvet_app (which is never the
// owner). A new RLS table shipped without it would re-break auth/reapers on the managed DB only — invisible
// to local tests — so this guard fails the build instead.
func TestOwnerBypassPolicy(t *testing.T) {
	db := connect(t)

	rows, err := db.Pool.Query(context.Background(), `
		SELECT c.relname
		FROM pg_class c
		WHERE c.relkind = 'r'
		  AND c.relnamespace = 'public'::regnamespace
		  AND c.relrowsecurity
		  AND NOT EXISTS (
		    SELECT 1 FROM pg_policies p
		    WHERE p.schemaname = 'public' AND p.tablename = c.relname AND p.policyname = 'owner_bypass'
		  )
		ORDER BY c.relname`)
	if err != nil {
		t.Fatalf("owner_bypass query: %v", err)
	}
	defer rows.Close()

	var missing []string
	for rows.Next() {
		var tbl string
		if err := rows.Scan(&tbl); err != nil {
			t.Fatalf("scan: %v", err)
		}
		missing = append(missing, tbl)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(missing) > 0 {
		t.Fatalf("RLS table without the owner_bypass policy (SECURITY DEFINER functions owned by the "+
			"non-superuser managed-DB owner would silently return zero rows — add the owner_bypass policy, "+
			"see migration 0118): %v", missing)
	}
}
