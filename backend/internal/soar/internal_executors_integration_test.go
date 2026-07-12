package soar_test

// #187 slice C — internal executor landing round (DB-gated). Proves the internal, non-destructive executors
// write a REAL, durable, tenant-scoped record (not a simulation) inside the run, and that the records are
// tenant-isolated (RLS).

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

// execSetup builds a service with the internal recorder registered for all internal action keys + a tenant.
func execSetup(t *testing.T) (*soar.Service, uuid.UUID, context.Context) {
	t.Helper()
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	repo := soar.NewRepository(db)
	ts := tenant.NewService(tenant.NewRepository(db))
	tn, err := ts.Create(ctx, tenant.CreateInput{Name: "exec-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	execs := soar.NewExecutors()
	rec := soar.NewInternalRecorder(repo)
	for _, k := range soar.InternalActionKeys() {
		execs.Register(k, rec)
	}
	svc := soar.NewService(repo).WithAuthorizer(ts).WithExecutors(execs)
	return svc, tn.ID, ctx
}

// The internal executor produces a REAL executed effect (not simulated) and a durable, listable record.
func TestExec_InternalRecorderWritesRealRecord(t *testing.T) {
	svc, tid, ctx := execSetup(t)
	if err := svc.SetAuthority(ctx, principal(tid, auth.RolePlatformAdmin), tid, soar.AuthorityApproval); err != nil {
		t.Fatalf("authority: %v", err)
	}
	pb, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name:  "notes",
		Steps: []soar.Step{stepIn("note it", "create_note", soar.RiskInformational, false)},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	run, err := svc.Run(ctx, mgr(tid), pb.ID, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if s := findStep(run, "note it"); s == nil || s.Status != soar.StatusExecuted {
		t.Fatalf("create_note must EXECUTE (real internal effect), not simulate; got %+v", s)
	}
	recs, err := svc.ListActionRecords(ctx, tid, 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(recs) != 1 || recs[0].Kind != "note" || recs[0].ActionKey != "create_note" {
		t.Fatalf("expected exactly one durable 'note' record; got %+v", recs)
	}
}

// Records are tenant-isolated: tenant B never sees tenant A's action records (RLS).
func TestExec_ActionRecordsTenantIsolated(t *testing.T) {
	svcA, tidA, ctx := execSetup(t)
	if err := svcA.SetAuthority(ctx, principal(tidA, auth.RolePlatformAdmin), tidA, soar.AuthorityApproval); err != nil {
		t.Fatalf("authority: %v", err)
	}
	pb, err := svcA.CreatePlaybook(ctx, mgr(tidA), tidA, soar.PlaybookInput{
		Name:  "enrich-it",
		Steps: []soar.Step{stepIn("enrich", "enrich", soar.RiskInformational, false)},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svcA.Run(ctx, mgr(tidA), pb.ID, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	if recs, _ := svcA.ListActionRecords(ctx, tidA, 100); len(recs) != 1 {
		t.Fatalf("tenant A should have 1 record; got %d", len(recs))
	}
	// A brand-new tenant B must see none of A's records.
	tidB := mustTenant(t, ctx)
	if recs, err := svcA.ListActionRecords(ctx, tidB, 100); err != nil || len(recs) != 0 {
		t.Fatalf("tenant B must see zero of tenant A's records (RLS); got %d err=%v", len(recs), err)
	}
}

// mustTenant makes a throwaway tenant using a fresh connection (kept tiny to avoid pool churn).
func mustTenant(t *testing.T, ctx context.Context) uuid.UUID {
	t.Helper()
	db, err := database.Connect(ctx, testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "b-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant B: %v", err)
	}
	return tn.ID
}
