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
	"regexp"
	"sort"
	"strings"
	"testing"

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
		"api_keys_prefix_key":             "api-key prefix is a global pre-tenant lookup (auth resolves the tenant from the key)",
		"user_invitations_token_hash_key": "invite token hash is a global pre-tenant lookup (validated before any tenant context)",
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
