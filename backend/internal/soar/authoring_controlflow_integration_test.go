package soar_test

// #187 slice B — control-flow adversarial landing round (DB-gated). Proves the reviewer's slice-B invariants:
//   - FAIL-CLOSED boundary: a `condition` in a playbook that contains a connector step is REJECTED (400) at
//     author time — never a silent run-time no-op (a single connector step routes the whole run supervised,
//     which doesn't evaluate conditions).
//   - CONDITION 2: a DENIED approval on a destructive step HALTS the run even with continue_on_failure=true — the
//     new flag must not walk past a denied containment.
//   - skip-only: a condition SKIPS a step (recorded `skipped`, not run), and never escalates/auto-runs.
//   - continue_on_failure governs EXECUTION failures only: default halts the run; =true keeps going.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// failingExec always errors, so a step it backs is recorded StatusFailed — the trigger for continue_on_failure.
type failingExec struct{}

func (failingExec) Execute(context.Context, pgx.Tx, uuid.UUID, string, map[string]any) (soar.Outcome, error) {
	return soar.Outcome{}, errors.New("boom")
}

// cfSetup builds a service with the given executor registry (nil = none) + a fresh tenant.
func cfSetup(t *testing.T, execs *soar.Executors) (*soar.Service, uuid.UUID, context.Context) {
	t.Helper()
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	ts := tenant.NewService(tenant.NewRepository(db))
	tn, err := ts.Create(ctx, tenant.CreateInput{Name: "cf-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	svc := soar.NewService(soar.NewRepository(db)).WithAuthorizer(ts)
	if execs != nil {
		svc = svc.WithExecutors(execs)
	}
	return svc, tn.ID, ctx
}

func condStep(name, action string, when, equals string) soar.Step {
	return soar.Step{Name: name, Action: action, Condition: &soar.StepCondition{WhenStep: when, EqualsStatus: equals}}
}

// findStep returns the recorded result for a step by name.
func findStep(run *soar.PlaybookRun, name string) *soar.StepResult {
	for i := range run.Steps {
		if run.Steps[i].Name == name {
			return &run.Steps[i]
		}
	}
	return nil
}

// FAIL-CLOSED boundary: a condition in a playbook containing a connector step → 400 (never silently ignored).
func TestCF_ConditionInConnectorPlaybookRejected(t *testing.T) {
	svc, tid, ctx := cfSetup(t, nil)
	_, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name: "mixed",
		Steps: []soar.Step{
			stepIn("enrich", "enrich", soar.RiskInformational, false),
			condStep("notify", "notify_analyst", "enrich", soar.StatusSimulated), // condition on an inline step...
			stepIn("isolate", "isolate_endpoint", soar.RiskHigh, true),           // ...but the playbook has a connector step
		},
	})
	if !statusIs(err, http.StatusBadRequest) {
		t.Fatalf("a condition in a playbook with a connector step must 400 (fail-closed); got %v", err)
	}
}

// A condition must reference a PRIOR step by name.
func TestCF_ConditionMustReferencePriorStep(t *testing.T) {
	svc, tid, ctx := cfSetup(t, nil)
	_, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name:  "bad-ref",
		Steps: []soar.Step{condStep("notify", "notify_analyst", "does_not_exist", soar.StatusExecuted)},
	})
	if !statusIs(err, http.StatusBadRequest) {
		t.Fatalf("a condition referencing a non-prior step must 400; got %v", err)
	}
}

// skip-only + discriminating: an unmet condition SKIPS the step; a met one runs it.
func TestCF_ConditionSkipsStepDiscriminating(t *testing.T) {
	svc, tid, ctx := cfSetup(t, nil) // no executor → enrich simulates
	if err := svc.SetAuthority(ctx, principal(tid, auth.RolePlatformAdmin), tid, soar.AuthorityApproval); err != nil {
		t.Fatalf("authority: %v", err)
	}
	// Unmet: notify runs only if enrich FAILED, but enrich simulates → notify SKIPPED.
	pbSkip, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name:  "cond-skip",
		Steps: []soar.Step{stepIn("enrich", "enrich", soar.RiskInformational, false), condStep("notify", "notify_analyst", "enrich", soar.StatusFailed)},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	runSkip, err := svc.Run(ctx, mgr(tid), pbSkip.ID, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if s := findStep(runSkip, "notify"); s == nil || s.Status != soar.StatusSkipped {
		t.Fatalf("notify should be SKIPPED when its condition is unmet; got %+v", s)
	}
	// Met: same but condition is enrich==simulated → notify RUNS (simulated, since no executor).
	pbRun, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name:  "cond-run",
		Steps: []soar.Step{stepIn("enrich", "enrich", soar.RiskInformational, false), condStep("notify", "notify_analyst", "enrich", soar.StatusSimulated)},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	runRun, err := svc.Run(ctx, mgr(tid), pbRun.ID, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if s := findStep(runRun, "notify"); s == nil || s.Status == soar.StatusSkipped {
		t.Fatalf("notify should RUN when its condition is met (discriminating); got %+v", s)
	}
}

// continue_on_failure: default halts the run at a failed step; =true keeps going.
func TestCF_ContinueOnFailure(t *testing.T) {
	execs := soar.NewExecutors().Register("enrich", failingExec{}) // make the enrich step fail
	// Default (halt): enrich fails → notify SKIPPED.
	svc, tid, ctx := cfSetup(t, execs)
	if err := svc.SetAuthority(ctx, principal(tid, auth.RolePlatformAdmin), tid, soar.AuthorityApproval); err != nil {
		t.Fatalf("authority: %v", err)
	}
	pbHalt, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name:  "halt",
		Steps: []soar.Step{stepIn("enrich", "enrich", soar.RiskInformational, false), stepIn("notify", "notify_analyst", soar.RiskLow, false)},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	runHalt, err := svc.Run(ctx, mgr(tid), pbHalt.ID, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if s := findStep(runHalt, "notify"); s == nil || s.Status != soar.StatusSkipped {
		t.Fatalf("notify must be SKIPPED when a prior step failed (default halt); got %+v", s)
	}
	// continue_on_failure=true on the failing step → notify runs anyway.
	failStep := stepIn("enrich", "enrich", soar.RiskInformational, false)
	failStep.ContinueOnFailure = true
	pbCont, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name:  "cont",
		Steps: []soar.Step{failStep, stepIn("notify", "notify_analyst", soar.RiskLow, false)},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	runCont, err := svc.Run(ctx, mgr(tid), pbCont.ID, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if s := findStep(runCont, "notify"); s == nil || s.Status == soar.StatusSkipped {
		t.Fatalf("notify must RUN past the failure when continue_on_failure=true; got %+v", s)
	}
}

// CONDITION 2 (reviewer headline): a denied destructive step halts the run even with continue_on_failure=true —
// the flag must not walk past a denied containment.
func TestCF_DeniedDestructiveHaltsEvenWithContinueOnFailure(t *testing.T) {
	svc, tid, ctx := cfSetup(t, nil)
	if err := svc.SetAuthority(ctx, principal(tid, auth.RolePlatformAdmin), tid, soar.AuthorityApproval); err != nil {
		t.Fatalf("authority: %v", err)
	}
	notify := stepIn("notify", "notify_analyst", soar.RiskLow, false)
	notify.ContinueOnFailure = true // the new flag, set on a step in the same run
	pb, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name:  "deny-halt",
		Steps: []soar.Step{stepIn("isolate", "isolate_endpoint", soar.RiskHigh, true), notify},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	run, err := svc.Run(ctx, mgr(tid), pb.ID, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if run.Status != soar.RunPendingApproval {
		t.Fatalf("destructive step should hold the run at pending_approval; got %q", run.Status)
	}
	// A DIFFERENT senior denies the containment.
	rejected, err := svc.Reject(ctx, principal(tid, auth.RoleSOCManager), run.ID)
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rejected.Status != soar.RunRejected {
		t.Fatalf("a denied run must be rejected; got %q", rejected.Status)
	}
	if s := findStep(rejected, "isolate"); s == nil || s.Status == soar.StatusExecuted {
		t.Fatalf("a denied destructive step must NOT execute; got %+v", s)
	}
}
