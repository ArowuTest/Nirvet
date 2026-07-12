package detection_test

// DET-002 stateful detection — adversarial landing round (DB-gated on NIRVET_TEST_DATABASE_URL). Proves the
// things a stateful eval path most easily gets wrong: fire-once-per-(entity,window), idempotent on event replay
// (no double-count), cross-tenant window isolation, distinct-count firing, and — the double-fire guard — that
// concurrent workers crossing the threshold on the same window fire EXACTLY ONE alert.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

func statefulSetup(t *testing.T) (*detection.Engine, *detection.Repository, *database.DB, context.Context) {
	t.Helper()
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	repo := detection.NewRepository(db)
	return detection.NewEngine(repo), repo, db, ctx
}

func failedAuth(tenantID uuid.UUID, user string) eventstore.NormalizedEvent {
	return eventstore.NormalizedEvent{
		ID: uuid.New(), TenantID: tenantID, ClassName: "Authentication", ActorRef: "user:" + user,
		Action: "signin", Outcome: "failure", ObservedAt: time.Now(),
	}
}

// createStatefulRule creates a TENANT-OWNED stateful rule (nirvet_app cannot insert global rules — that's the
// migration owner's job, correctly blocked by RLS) whose base condition matches a failed Authentication event.
func createStatefulRule(t *testing.T, repo *detection.Repository, ctx context.Context, tenantID uuid.UUID, kind string, window, threshold int, entityField, distinctField string) {
	t.Helper()
	rule := &detection.Rule{
		ID: uuid.New(), Name: kind + "-" + uuid.NewString()[:8], Severity: "high", Confidence: 80,
		Enabled: true, Stage: detection.StageProduction,
		Kind: kind, WindowSeconds: window, Threshold: threshold, EntityField: entityField, DistinctField: distinctField,
		Condition: detection.Condition{All: []detection.Predicate{
			{Field: "class_name", Op: detection.OpEq, Value: "Authentication"},
			{Field: "outcome", Op: detection.OpEq, Value: "failure"},
		}},
	}
	if err := repo.Create(ctx, tenantID, rule); err != nil {
		t.Fatalf("create stateful rule: %v", err)
	}
}

func TestStateful_ThresholdFiresOnceAndIsIdempotent(t *testing.T) {
	engine, repo, db, ctx := statefulSetup(t)
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "st-" + uuid.NewString()})
	createStatefulRule(t, repo, ctx, tn.ID, detection.KindThreshold, 300, 3, "actor_ref", "")

	fireCount := 0
	feed := func(ev eventstore.NormalizedEvent) {
		m, err := engine.EvaluateStateful(ctx, tn.ID, ev)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		fireCount += len(m)
	}
	e1, e2, e3, e4 := failedAuth(tn.ID, "alice"), failedAuth(tn.ID, "alice"), failedAuth(tn.ID, "alice"), failedAuth(tn.ID, "alice")
	feed(e1) // count 1 — no fire
	feed(e2) // count 2 — no fire
	if fireCount != 0 {
		t.Fatalf("fired before threshold (%d)", fireCount)
	}
	feed(e3) // count 3 — FIRE
	if fireCount != 1 {
		t.Fatalf("expected exactly one fire at threshold, got %d", fireCount)
	}
	feed(e4) // already fired this window — latch holds
	feed(e3) // REPLAY the firing event — idempotent, no double count, no re-fire
	feed(e1) // replay an earlier event too
	if fireCount != 1 {
		t.Fatalf("fired more than once (latch/idempotency broken): %d", fireCount)
	}
	// A DIFFERENT user in the same tenant/window is a separate entity → its own count, no fire yet.
	feed(failedAuth(tn.ID, "bob"))
	if fireCount != 1 {
		t.Fatalf("a different entity should not share alice's window: %d", fireCount)
	}
}

func TestStateful_CrossTenantWindowIsolation(t *testing.T) {
	engine, repo, db, ctx := statefulSetup(t)
	ts := tenant.NewService(tenant.NewRepository(db))
	tA, _ := ts.Create(ctx, tenant.CreateInput{Name: "sta-" + uuid.NewString()})
	tB, _ := ts.Create(ctx, tenant.CreateInput{Name: "stb-" + uuid.NewString()})
	createStatefulRule(t, repo, ctx, tA.ID, detection.KindThreshold, 300, 3, "actor_ref", "")
	createStatefulRule(t, repo, ctx, tB.ID, detection.KindThreshold, 300, 3, "actor_ref", "")

	count := func(tid uuid.UUID) int {
		m, err := engine.EvaluateStateful(ctx, tid, failedAuth(tid, "alice"))
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		return len(m)
	}
	// 3 alice-failures in A → A fires. B only gets 2 → B must NOT fire (separate per-tenant window).
	got := count(tA.ID) + count(tA.ID) + count(tA.ID)
	if got != 1 {
		t.Fatalf("tenant A should fire once at threshold, got %d", got)
	}
	if b := count(tB.ID) + count(tB.ID); b != 0 {
		t.Fatalf("tenant B (2 events) must not fire — window is per-tenant; got %d", b)
	}
}

func TestStateful_DistinctFires(t *testing.T) {
	engine, repo, db, ctx := statefulSetup(t)
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "std-" + uuid.NewString()})
	createStatefulRule(t, repo, ctx, tn.ID, detection.KindDistinct, 3600, 2, "actor_ref", "data.country")

	sign := func(country string) int {
		ev := failedAuth(tn.ID, "carol")
		ev.Data = map[string]any{"country": country}
		m, _ := engine.EvaluateStateful(ctx, tn.ID, ev)
		return len(m)
	}
	if n := sign("GH") + sign("GH"); n != 0 { // same country twice → distinct=1
		t.Fatalf("same country should not reach distinct threshold, got %d", n)
	}
	if n := sign("RU"); n != 1 { // second distinct country → FIRE
		t.Fatalf("second distinct country should fire once, got %d", n)
	}
}

func TestStateful_ConcurrentThresholdFiresExactlyOnce(t *testing.T) {
	engine, repo, db, ctx := statefulSetup(t)
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "stc-" + uuid.NewString()})
	createStatefulRule(t, repo, ctx, tn.ID, detection.KindThreshold, 300, 5, "actor_ref", "")

	// 20 concurrent distinct failed-auth events for the same user in the same window. The window crosses the
	// threshold of 5; the fired_at latch must ensure EXACTLY ONE goroutine observes a fire (double-fire guard).
	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	fires := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := engine.EvaluateStateful(ctx, tn.ID, failedAuth(tn.ID, "dave"))
			if err == nil && len(m) > 0 {
				mu.Lock()
				fires += len(m)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if fires != 1 {
		t.Fatalf("concurrent threshold crossing must fire EXACTLY once (double-fire guard), got %d", fires)
	}
}
