package soar

// §6.11 slice B MUST-2 ordering — evidence-before-isolate + crash-mid-run resume-in-order. Internal test
// (package soar) so it can drive advanceRun directly with hand-built plans.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// recExec is an internal ActionExecutor that records its invocation order (the "collect evidence" step).
type recExec struct{ order *[]string }

func (r *recExec) Execute(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, action string, params map[string]any) (Outcome, error) {
	*r.order = append(*r.order, "evidence")
	return Outcome{Executed: true, Detail: "evidence collected"}, nil
}

func orderingSetup(t *testing.T) (*database.DB, uuid.UUID) {
	t.Helper()
	dsn := testsupport.RequireDSN(t)
	db, err := database.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "ord-" + uuid.NewString()})
	return db, tn.ID
}

func orderingPlans(order *[]string) (*ActionerRegistry, *Executors, []stepPlan) {
	reg := NewActionerRegistry().Register(Actioner{ConnectorKey: "defender", Action: "isolate", Idempotent: true, PreCheck: true, Reversible: true, Inverse: "release",
		Fn: func(context.Context, []byte, string, map[string]any) (string, map[string]any, error) {
			*order = append(*order, "isolate")
			return "iso-ref", map[string]any{"changed": true}, nil
		}})
	execs := NewExecutors().Register("collect_evidence", &recExec{order: order})
	plans := []stepPlan{
		{act: ActionCatalog{ActionKey: "collect_evidence", RiskClass: RiskInformational, Executor: ExecutorInternal}, auto: true,
			sr: StepResult{Name: "collect_evidence", Action: "collect_evidence", Risk: RiskInformational}},
		{act: ActionCatalog{ActionKey: "isolate", ConnectorKey: "defender", RiskClass: RiskHigh, Executor: ExecutorConnector}, auto: true, target: "host:h1",
			sr: StepResult{Name: "isolate", ConnectorKey: "defender", Action: "isolate", Risk: RiskHigh}},
	}
	return reg, execs, plans
}

func TestAdvanceRun_EvidenceBeforeIsolate(t *testing.T) {
	db, tid := orderingSetup(t)
	ctx := context.Background()
	repo := NewRepository(db)
	_ = repo.SetSoarSettings(ctx, tid, SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})
	order := []string{}
	reg, execs, plans := orderingPlans(&order)
	sup := NewSupervisor(repo, reg, nil, nil)
	svc := NewService(repo).WithExecutors(execs).WithSupervisor(sup)

	run := &PlaybookRun{ID: uuid.New(), TenantID: tid, PlaybookID: uuid.New(), Status: RunRunning,
		Steps: []StepResult{plans[0].sr, plans[1].sr}}
	if err := repo.RunTx(ctx, tid, func(ctx context.Context, tx pgx.Tx) error { return repo.insertRunTx(ctx, tx, run) }); err != nil {
		t.Fatalf("insert run: %v", err)
	}
	p := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	svc.advanceRun(ctx, p, run, plans, nil, 0)

	if len(order) != 2 || order[0] != "evidence" || order[1] != "isolate" {
		t.Fatalf("MUST-2 ordering violated: expected [evidence isolate], got %v", order)
	}
	if run.Status != RunCompleted {
		t.Fatalf("run should complete, got %s", run.Status)
	}
	if run.Steps[0].Status != StatusExecuted || run.Steps[1].Status != StatusExecuted {
		t.Fatalf("both steps should execute, got %s / %s", run.Steps[0].Status, run.Steps[1].Status)
	}
}

// TestAdvanceRun_ResumeInOrder: a run where the internal step already ran (crash before the connector
// step) resumes and drives ONLY the connector step — the evidence step is not re-run (in order, once each).
func TestAdvanceRun_ResumeInOrder(t *testing.T) {
	db, tid := orderingSetup(t)
	ctx := context.Background()
	repo := NewRepository(db)
	_ = repo.SetSoarSettings(ctx, tid, SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})
	order := []string{}
	reg, execs, plans := orderingPlans(&order)
	sup := NewSupervisor(repo, reg, nil, nil)
	svc := NewService(repo).WithExecutors(execs).WithSupervisor(sup)

	// Step 0 already executed on the prior pass; the run resumes at the connector step.
	run := &PlaybookRun{ID: uuid.New(), TenantID: tid, PlaybookID: uuid.New(), Status: RunRunning,
		Steps: []StepResult{{Name: "collect_evidence", Action: "collect_evidence", Status: StatusExecuted}, plans[1].sr}}
	if err := repo.RunTx(ctx, tid, func(ctx context.Context, tx pgx.Tx) error { return repo.insertRunTx(ctx, tx, run) }); err != nil {
		t.Fatalf("insert run: %v", err)
	}
	p := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	svc.advanceRun(ctx, p, run, plans, nil, 0)

	if len(order) != 1 || order[0] != "isolate" {
		t.Fatalf("resume must run ONLY the connector step (evidence already done), got %v", order)
	}
	if run.Status != RunCompleted {
		t.Fatalf("run should complete, got %s", run.Status)
	}
}
