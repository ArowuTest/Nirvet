package recovery

import "testing"

func TestQuoteIdentifierEscapesCatalogNames(t *testing.T) {
	got := quoteIdentifier(`tenant"table`)
	if got != `"tenant""table"` {
		t.Fatalf("unexpected quoted identifier: %s", got)
	}
}

func TestTenantNullabilityComesFromRestoredSchema(t *testing.T) {
	required := tenantTable{Name: "incidents", TenantNotNull: true}
	globalCapable := tenantTable{Name: "content_packages", TenantNotNull: false}
	if !required.TenantNotNull {
		t.Fatal("required tenant table must be checked for NULL contamination")
	}
	if globalCapable.TenantNotNull {
		t.Fatal("nullable global-capable table must not be treated as contaminated solely for NULL tenant rows")
	}
}

func TestPreTenantRLSExceptionsAreExplicit(t *testing.T) {
	for _, table := range []string{"ingest_jobs", "syslog_sources", "tenant_offboarding"} {
		if !isPreTenantRLSException(table) {
			t.Fatalf("expected %s to be an intentional pre-tenant exception", table)
		}
	}
	for _, table := range []string{"events", "incidents", "content_packages", "new_unknown_table"} {
		if isPreTenantRLSException(table) {
			t.Fatalf("unexpected pre-tenant exception for %s", table)
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
