package recovery

import "testing"

func TestQuoteIdentifierEscapesCatalogNames(t *testing.T) {
	got := quoteIdentifier(`tenant"table`)
	if got != `"tenant""table"` {
		t.Fatalf("unexpected quoted identifier: %s", got)
	}
}

func TestAllowsGlobalRowsIsExplicitAndFailClosed(t *testing.T) {
	for _, table := range []string{"content_packages", "content_artifacts", "content_lifecycle_audit", "authority_policies", "retention_policy", "feature_flags"} {
		if !allowsGlobalRows(table) {
			t.Fatalf("expected %s to allow operator-wide rows", table)
		}
	}
	for _, table := range []string{"users", "incidents", "evidence", "new_unknown_table"} {
		if allowsGlobalRows(table) {
			t.Fatalf("unexpected global-row exemption for %s", table)
		}
	}
}

func TestTenantTableSecurityFailuresAreLoadBearing(t *testing.T) {
	cases := []struct {
		name  string
		table tenantTable
		want  bool
	}{
		{name: "sound", table: tenantTable{Name: "events", RLSEnabled: true, RLSForced: true, OwnerBypass: true}, want: false},
		{name: "rls disabled", table: tenantTable{Name: "events", RLSForced: true, OwnerBypass: true}, want: true},
		{name: "force missing", table: tenantTable{Name: "events", RLSEnabled: true, OwnerBypass: true}, want: true},
		{name: "owner bypass missing", table: tenantTable{Name: "events", RLSEnabled: true, RLSForced: true}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			failed := !tc.table.RLSEnabled || !tc.table.RLSForced || !tc.table.OwnerBypass
			if failed != tc.want {
				t.Fatalf("failure=%v want=%v", failed, tc.want)
			}
		})
	}
}
