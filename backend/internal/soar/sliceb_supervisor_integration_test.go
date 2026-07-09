package soar_test

// §6.11 slice B supervisor engine — the adversarial acceptance bar, against a migrated Postgres.
// Each test reproduces one invariant from the design gate and proves it holds.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type mockCreds struct{}

func (mockCreds) ConnectorCreds(context.Context, uuid.UUID, string) ([]byte, error) {
	return []byte("secret"), nil
}

// callCounter counts real Actioner invocations so a test can assert "the external effect happened
// exactly N times" — the core of every crash/idempotency/withhold proof.
type callCounter struct{ n int }

func (c *callCounter) actioner(connectorKey, action string, idempotent bool) soar.Actioner {
	return soar.Actioner{
		ConnectorKey: connectorKey, Action: action, Idempotent: idempotent, PreCheck: idempotent,
		Reversible: true, Inverse: "reverse",
		Fn: func(context.Context, []byte, string, map[string]any) (string, map[string]any, error) {
			c.n++
			return "ref-123", map[string]any{"was_isolated": false}, nil
		},
	}
}

func setupSup(t *testing.T) (*soar.Supervisor, *soar.Repository, *database.DB, uuid.UUID, *callCounter) {
	t.Helper()
	dsn := testsupport.RequireDSN(t)
	db, err := database.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	// Reset the global kill-switch after (single shared row).
	repo := soar.NewRepository(db)
	t.Cleanup(func() { _ = repo.SetPlatformFlags(context.Background(), soar.PlatformFlags{}) })
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "sup-" + uuid.NewString()})
	cc := &callCounter{}
	reg := soar.NewActionerRegistry().Register(cc.actioner("defender", "isolate", true))
	sup := soar.NewSupervisor(repo, reg, mockCreds{}, nil)
	return sup, repo, db, tn.ID, cc
}

func hiAct() soar.ActionCatalog {
	return soar.ActionCatalog{ActionKey: "isolate", ConnectorKey: "defender", RiskClass: soar.RiskHigh, Executor: soar.ExecutorConnector, Enabled: true}
}

func TestSupervisor_LiveHappyPath(t *testing.T) {
	sup, repo, _, tid, cc := setupSup(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	_ = repo.SetSoarSettings(ctx, tid, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})

	st, note, err := sup.ExecuteConnectorStep(ctx, tid, actor, uuid.New(), 0, hiAct(), "host:h1", nil)
	if err != nil || st != soar.StatusExecuted {
		t.Fatalf("live happy path: status=%s note=%q err=%v", st, note, err)
	}
	if cc.n != 1 {
		t.Fatalf("actioner must be called exactly once, got %d", cc.n)
	}
}

func TestSupervisor_DisabledWithholds(t *testing.T) {
	sup, _, _, tid, cc := setupSup(t) // destructive_enabled defaults OFF
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, uuid.New(), 0, hiAct(), "host:h1", nil)
	if err != nil || st != soar.StatusWithheld {
		t.Fatalf("disabled tenant must withhold, got %s (err %v)", st, err)
	}
	if cc.n != 0 {
		t.Fatal("no real effect when withheld")
	}
}

func TestSupervisor_RateLimitWithholds(t *testing.T) {
	sup, repo, _, tid, cc := setupSup(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	_ = repo.SetSoarSettings(ctx, tid, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 1})
	// First fires; second is over budget → withheld, no second call.
	if st, _, _ := sup.ExecuteConnectorStep(ctx, tid, actor, uuid.New(), 0, hiAct(), "host:h1", nil); st != soar.StatusExecuted {
		t.Fatalf("first should execute, got %s", st)
	}
	if st, _, _ := sup.ExecuteConnectorStep(ctx, tid, actor, uuid.New(), 0, hiAct(), "host:h2", nil); st != soar.StatusWithheld {
		t.Fatalf("second should be rate-withheld, got %s", st)
	}
	if cc.n != 1 {
		t.Fatalf("only the first (budgeted) action fires, got %d calls", cc.n)
	}
}

func TestSupervisor_NonIdempotentForcedManual(t *testing.T) {
	sup, repo, db, tid, _ := setupSup(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	_ = repo.SetSoarSettings(ctx, tid, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})
	// A registry whose action is NOT idempotent → contract refuses auto-run → awaiting_customer, no call.
	nc := &callCounter{}
	reg := soar.NewActionerRegistry().Register(soar.Actioner{ConnectorKey: "flaky", Action: "block", Idempotent: false, PreCheck: false,
		Fn: func(context.Context, []byte, string, map[string]any) (string, map[string]any, error) {
			nc.n++
			return "x", nil, nil
		}})
	sup2 := soar.NewSupervisor(soar.NewRepository(db), reg, mockCreds{}, nil)
	act := soar.ActionCatalog{ActionKey: "block", ConnectorKey: "flaky", RiskClass: soar.RiskHigh, Executor: soar.ExecutorConnector, Enabled: true}
	st, _, err := sup2.ExecuteConnectorStep(ctx, tid, actor, uuid.New(), 0, act, "ip:1.2.3.4", nil)
	if err != nil || st != soar.StatusAwaitingCustomer {
		t.Fatalf("non-idempotent must be forced to manual, got %s (err %v)", st, err)
	}
	if nc.n != 0 {
		t.Fatal("no real effect for a manual-forced action")
	}
	_ = sup
}

func TestSupervisor_DryRunNoEffect(t *testing.T) {
	sup, repo, _, tid, cc := setupSup(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	_ = repo.SetSoarSettings(ctx, tid, soar.SoarSettings{DestructiveEnabled: false, DryRun: true, MaxClass3PerHour: 5})
	st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, uuid.New(), 0, hiAct(), "host:h1", nil)
	if err != nil || st != soar.StatusSimulated {
		t.Fatalf("dry-run must simulate, got %s (err %v)", st, err)
	}
	if cc.n != 0 {
		t.Fatal("dry-run makes no real call")
	}
}

// TestSupervisor_KillSwitchMidFlight: a step CLAIMED (crash left it 'executing') then the kill-switch is
// engaged must ABORT at Phase B without calling the connector (emergency stop for claimed-not-executed).
func TestSupervisor_KillSwitchMidFlight(t *testing.T) {
	sup, repo, db, tid, cc := setupSup(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	runID := uuid.New()
	seedExecuting(t, db, tid, runID, 0) // simulate a crash right after Phase A claim
	_ = repo.SetPlatformFlags(ctx, soar.PlatformFlags{KillSwitch: true})
	st, note, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, hiAct(), "host:h1", nil)
	if err != nil || st != soar.StatusFailed {
		t.Fatalf("kill-switch mid-flight must abort (failed), got %s note=%q err=%v", st, note, err)
	}
	if cc.n != 0 {
		t.Fatal("kill-switch mid-flight must NOT call the connector")
	}
}

// TestSupervisor_CrashResumeClaimOnce: an 'executing' row (crash after claim) resumes at Phase B, calls
// the idempotent actioner ONCE, and a subsequent invocation reflects the terminal state (no second call).
func TestSupervisor_CrashResumeClaimOnce(t *testing.T) {
	sup, repo, db, tid, cc := setupSup(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	_ = repo.SetSoarSettings(ctx, tid, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})
	runID := uuid.New()
	seedExecuting(t, db, tid, runID, 0)
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, hiAct(), "host:h1", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("resume should execute, got %s (err %v)", st, err)
	}
	if st, _, _ := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, hiAct(), "host:h1", nil); st != soar.StatusExecuted {
		t.Fatalf("replay should reflect executed, got %s", st)
	}
	if cc.n != 1 {
		t.Fatalf("resume + replay must call the connector exactly once, got %d", cc.n)
	}
}

// seedExecuting inserts a claimed-but-unexecuted execution row (simulating a crash after Phase A).
func seedExecuting(t *testing.T, db *database.DB, tenantID, runID uuid.UUID, step int) {
	t.Helper()
	if err := db.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO soar_action_execution (tenant_id, run_id, step_index, action_key, connector_key, target, risk_class, status)
			 VALUES ($1,$2,$3,'isolate','defender','host:h1','high','executing')`, tenantID, runID, step)
		return e
	}); err != nil {
		t.Fatalf("seed executing: %v", err)
	}
}
