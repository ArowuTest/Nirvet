package ai

// §6.12 #188 HEAVY-1 — AI-egress redaction integration (DB-gated). Proves the CONFIG-EXTENSIBLE pattern set is
// real (the seeded global Ghana Card pattern masks; a tenant-added pattern masks too — no code change), the
// policy resolver returns the global mask-by-default for a fresh tenant, and an explicit `off` is honoured.

import (
	"context"
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

func redDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func redTenant(t *testing.T, db *database.DB) (auth.Principal, uuid.UUID) {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "red-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return auth.Principal{TenantID: tn.ID, UserID: uuid.New(), Email: "a@red", Role: auth.RolePlatformAdmin}, tn.ID
}

// A fresh tenant inherits the seeded global mask-by-default (balanced), and the seeded GLOBAL Ghana Card pattern
// masks a GHA-… token — config-extensibility ships (no code change needed for the pilot).
func TestRedaction_GlobalDefaultAndSeededGhanaPattern(t *testing.T) {
	db := redDB(t)
	svc := NewRedactionService(db)
	_, tid := redTenant(t, db)
	ctx := context.Background()

	pol := svc.ResolvePolicy(ctx, tid)
	if !pol.Enabled || pol.Mode != RedactBalanced {
		t.Fatalf("fresh tenant must inherit global balanced default; got %+v", pol)
	}
	pats := svc.Patterns(ctx, tid)
	out, rr := redactLines([]string{"note=card GHA-123456789-1 on file"}, pol, pats)
	if strings.Contains(out[0], "GHA-123456789-1") {
		t.Fatalf("seeded Ghana Card pattern must mask the NID: %q", out[0])
	}
	if !strings.Contains(out[0], "GHANA_NID_") || rr.Count == 0 {
		t.Fatalf("expected a GHANA_NID_ placeholder: %q (%+v)", out[0], rr)
	}
}

// A tenant-added pattern (validated + compiled server-side) masks — extensibility at runtime, not just seed.
func TestRedaction_TenantAddedPatternMasks(t *testing.T) {
	db := redDB(t)
	svc := NewRedactionService(db)
	p, tid := redTenant(t, db)
	ctx := context.Background()

	if _, err := svc.AddPattern(ctx, p, "emp_badge", `EMP-[0-9]{6}`, "BADGE"); err != nil {
		t.Fatalf("add pattern: %v", err)
	}
	// A bad regex is rejected (fail-safe: never persist an un-compilable pattern).
	if _, err := svc.AddPattern(ctx, p, "bad", `EMP-[0-9`, "BADGE"); err == nil {
		t.Fatal("an un-compilable regex must be rejected")
	}
	pol := svc.ResolvePolicy(ctx, tid)
	out, _ := redactLines([]string{"note=badge EMP-004521 seen"}, pol, svc.Patterns(ctx, tid))
	if strings.Contains(out[0], "EMP-004521") || !strings.Contains(out[0], "BADGE_") {
		t.Fatalf("tenant-added pattern must mask EMP-004521 → BADGE_n: %q", out[0])
	}
}

// SetPolicy off is honoured (explicit, audited egress choice); SetPolicy strict resolves to strict.
func TestRedaction_SetPolicyOffAndStrict(t *testing.T) {
	db := redDB(t)
	svc := NewRedactionService(db)
	p, tid := redTenant(t, db)
	ctx := context.Background()

	if _, err := svc.SetPolicy(ctx, p, true, RedactOff); err != nil {
		t.Fatalf("set off: %v", err)
	}
	if pol := svc.ResolvePolicy(ctx, tid); pol.Mode != RedactOff {
		t.Fatalf("policy should resolve to off; got %+v", pol)
	}
	if _, err := svc.SetPolicy(ctx, p, true, RedactStrict); err != nil {
		t.Fatalf("set strict: %v", err)
	}
	if pol := svc.ResolvePolicy(ctx, tid); pol.Mode != RedactStrict {
		t.Fatalf("policy should resolve to strict; got %+v", pol)
	}
	// An invalid mode is rejected.
	if _, err := svc.SetPolicy(ctx, p, true, "loose"); err == nil {
		t.Fatal("invalid mode must be rejected")
	}
}

// A tenant's own pattern is tenant-isolated: another tenant does not see it (RLS), only the global ones.
func TestRedaction_PatternTenantIsolation(t *testing.T) {
	db := redDB(t)
	svc := NewRedactionService(db)
	a, _ := redTenant(t, db)
	_, tidB := redTenant(t, db)
	ctx := context.Background()

	if _, err := svc.AddPattern(ctx, a, "secretA", `AAA-[0-9]{4}`, "AONLY"); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Tenant B's effective patterns must NOT include tenant A's private pattern (it stays raw for B).
	out, _ := redactLines([]string{"note=code AAA-1234"}, svc.ResolvePolicy(ctx, tidB), svc.Patterns(ctx, tidB))
	if strings.Contains(out[0], "AONLY_") {
		t.Fatalf("tenant B must NOT get tenant A's private pattern (RLS): %q", out[0])
	}
}
