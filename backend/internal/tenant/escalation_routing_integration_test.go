package tenant

// #188 category-scoped notification routing landing round (DB-gated). Proves ResolveEscalationFor: a categorised
// notification reaches general + same-category contacts only (never a foreign-category on-call), an empty category
// broadcasts to all, and the severity threshold still gates. ResolveEscalation stays a pure broadcast (backward
// compat) so existing callers (incident SLA path, cred-expiry) are unchanged.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/google/uuid"
)

func routingSetup(t *testing.T) (*Service, auth.Principal, uuid.UUID) {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	svc := NewService(NewRepository(db))
	tn, err := svc.Create(context.Background(), CreateInput{Name: "route-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	p := auth.Principal{TenantID: tn.ID, UserID: uuid.New(), Email: "a@b.co", Role: auth.RolePlatformAdmin}
	// general (all categories, min low), identity-scoped (min low), network-scoped (min high).
	add := func(name, cat, minSev string) {
		if _, err := svc.AddEscalationContact(context.Background(), p, tn.ID, EscalationInput{
			Name: name, MinSeverity: minSev, Channel: "email", Address: name + "@ops.co", Category: cat,
		}); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}
	add("general", "", "low")
	add("identity", "identity", "low")
	add("network", "network", "high")
	return svc, p, tn.ID
}

func TestRouting_CategoryScoped(t *testing.T) {
	svc, _, tid := routingSetup(t)
	ctx := context.Background()

	got := func(sev, cat string) map[string]bool {
		targets, err := svc.ResolveEscalationFor(ctx, tid, sev, cat)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		m := map[string]bool{}
		for _, x := range targets {
			m[x.Address] = true
		}
		return m
	}

	// A network incident at critical → general + network, NEVER identity.
	if m := got("critical", "network"); !m["general@ops.co"] || !m["network@ops.co"] || m["identity@ops.co"] || len(m) != 2 {
		t.Fatalf("network/critical should reach general+network only; got %v", m)
	}
	// An identity incident at critical → general + identity, NEVER network.
	if m := got("critical", "identity"); !m["general@ops.co"] || !m["identity@ops.co"] || m["network@ops.co"] || len(m) != 2 {
		t.Fatalf("identity/critical should reach general+identity only; got %v", m)
	}
	// Empty category = broadcast → all three.
	if m := got("critical", ""); len(m) != 3 {
		t.Fatalf("broadcast should reach all 3 contacts; got %v", m)
	}
	// Severity threshold still gates: a low-severity network incident → general only (network is min high).
	if m := got("low", "network"); !m["general@ops.co"] || m["network@ops.co"] || len(m) != 1 {
		t.Fatalf("low severity must not reach the high-min network contact; got %v", m)
	}
	// Backward compat: ResolveEscalation is a pure broadcast (category-agnostic) → all three.
	bt, _ := svc.ResolveEscalation(ctx, tid, "critical")
	if len(bt) != 3 {
		t.Fatalf("ResolveEscalation must broadcast to all 3 (backward compat); got %d", len(bt))
	}
}
