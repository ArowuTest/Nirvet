package soar_test

// §6.11 slice B MUST-3 reverse — the reverse-wrong-way proof.

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestSupervisor_ReverseWrongWay: reverse undoes an isolate that CHANGED state (calls release), but SKIPS
// an isolate that was a no-op because the target was already isolated (prior_state.changed=false) — it
// must NOT "release" (re-enable) something the customer/env had independently put in that state.
func TestSupervisor_ReverseWrongWay(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run reverse tests")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "rev-" + uuid.NewString()})
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tn.ID}

	release := &callCounter{}
	reg := soar.NewActionerRegistry().
		Register(soar.Actioner{ConnectorKey: "defender", Action: "isolate", Idempotent: true, PreCheck: true, Reversible: true, Inverse: "release",
			Fn: func(context.Context, []byte, string, map[string]any) (string, map[string]any, error) { return "iso", nil, nil }}).
		Register(soar.Actioner{ConnectorKey: "defender", Action: "release", Idempotent: true, PreCheck: true,
			Fn: func(context.Context, []byte, string, map[string]any) (string, map[string]any, error) { release.n++; return "rel", nil, nil }})
	sup := soar.NewSupervisor(soar.NewRepository(db), reg, mockCreds{}, nil)

	// Case A: isolate that actually changed state → reverse calls release.
	runA := uuid.New()
	seedExecuted(t, db, tn.ID, runA, 0, map[string]any{"changed": true})
	resA, err := sup.ReverseRun(ctx, tn.ID, actor, runA)
	if err != nil || len(resA) != 1 || resA[0].Status != "reversed" {
		t.Fatalf("changed-state isolate must reverse, got %+v (err %v)", resA, err)
	}
	if release.n != 1 {
		t.Fatalf("release must be called once, got %d", release.n)
	}

	// Case B: isolate that was a no-op (host already isolated) → reverse SKIPS; release NOT called again.
	runB := uuid.New()
	seedExecuted(t, db, tn.ID, runB, 0, map[string]any{"changed": false})
	resB, err := sup.ReverseRun(ctx, tn.ID, actor, runB)
	if err != nil || len(resB) != 1 || resB[0].Status != "skipped_noop" {
		t.Fatalf("no-op isolate must be skipped, got %+v (err %v)", resB, err)
	}
	if release.n != 1 {
		t.Fatalf("release must NOT be called for a no-op reverse; got %d total", release.n)
	}
}

// seedExecuted inserts an executed, reversible connector execution row with the given prior_state.
func seedExecuted(t *testing.T, db *database.DB, tenantID, runID uuid.UUID, step int, priorState map[string]any) {
	t.Helper()
	prior, _ := json.Marshal(priorState)
	if err := db.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO soar_action_execution
			   (tenant_id, run_id, step_index, action_key, connector_key, target, risk_class, status, connector_ref, prior_state)
			 VALUES ($1,$2,$3,'isolate','defender','host:h1','high','executed','iso',$4)`, tenantID, runID, step, prior)
		return e
	}); err != nil {
		t.Fatalf("seed executed: %v", err)
	}
}
