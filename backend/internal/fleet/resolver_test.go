package fleet

// The scope-resolver is where the BOLA now lives (the SD-fn only enforces the bound). This is the reviewer's
// resolver-landing-round adversarial focus, proven: scope is derived PURELY from the principal; provider staff
// get the fleet; customer/unknown principals get an EMPTY set → the SD-fn's fail-closed → zero fleet alerts —
// never widened, never client-driven.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

func TestScopeResolver_ProviderGetsFleet_NonProviderEmpty(t *testing.T) {
	db := fleetDB(t)
	svc := NewService(db)
	res := &ScopeResolver{db: db}
	ctx := context.Background()

	tid := mkTenant(t, db)
	mkAlert(t, db, tid, "fleet-visible")

	// PROVIDER / SOC roles → the fleet (must include the fresh tenant's alert).
	for _, role := range []auth.Role{auth.RolePlatformAdmin, auth.RoleSOCManager, auth.RoleAnalystT1, auth.RoleAnalystT3, auth.RoleDetectionEng} {
		set, err := res.Resolve(ctx, auth.Principal{UserID: uuid.New(), TenantID: tid, Role: role})
		if err != nil {
			t.Fatalf("resolve %s: %v", role, err)
		}
		if len(set) == 0 {
			t.Fatalf("provider role %s must resolve to a non-empty fleet scope", role)
		}
		alerts, err := svc.Alerts(ctx, auth.Principal{UserID: uuid.New(), TenantID: tid, Role: role}, "", 500)
		if err != nil {
			t.Fatalf("fleet alerts %s: %v", role, err)
		}
		seen := false
		for _, a := range alerts {
			if a.TenantID == tid {
				seen = true
			}
		}
		if !seen {
			t.Fatalf("provider role %s fleet read must include the seeded tenant's alert", role)
		}
	}

	// CUSTOMER + unknown roles → EMPTY scope → zero fleet alerts (the reviewer's #2). The customer's principal
	// even carries a TenantID that HAS an alert — the fleet read still returns zero, because the fleet path is
	// operator-only and the resolver never widens a non-provider's scope.
	for _, role := range []auth.Role{auth.RoleCustomerAdmin, auth.RoleCustomerViewer, auth.Role("garbage_role"), auth.Role("")} {
		set, err := res.Resolve(ctx, auth.Principal{UserID: uuid.New(), TenantID: tid, Role: role})
		if err != nil {
			t.Fatalf("resolve %q: %v", role, err)
		}
		if len(set) != 0 {
			t.Fatalf("non-provider role %q MUST resolve to an EMPTY scope, got %d", role, len(set))
		}
		alerts, err := svc.Alerts(ctx, auth.Principal{UserID: uuid.New(), TenantID: tid, Role: role}, "", 500)
		if err != nil {
			t.Fatalf("fleet alerts %q: %v", role, err)
		}
		if len(alerts) != 0 {
			t.Fatalf("non-provider role %q fleet read MUST be empty (fail-closed), got %d", role, len(alerts))
		}
	}
}
