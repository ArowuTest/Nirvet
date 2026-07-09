package connector

// §6.4 #118 H-3 — host-source silence sweep (US-032). RunOnce is system-level (sweeps all tenants), so the
// assertions target THIS test's own connectors by id, never a global count.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type mockSilenceAlerter struct {
	mu      sync.Mutex
	targets map[string]int
}

func (m *mockSilenceAlerter) RaisePlatform(_ context.Context, _ uuid.UUID, _, _, _, targetRef, _ string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.targets == nil {
		m.targets = map[string]int{}
	}
	m.targets[targetRef]++
	return true, nil
}

func (m *mockSilenceAlerter) count(target string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.targets[target]
}

func silDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func insertHostConnector(t *testing.T, db *database.DB, tid, id uuid.UUID, ageMinutes int) {
	t.Helper()
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO connector_configs (id, tenant_id, kind, name, direction, enabled, config, health, last_success)
			VALUES ($1,$2,'host_osquery','agents','push',true,'{}','healthy', now() - make_interval(mins => $3))`, id, tid, ageMinutes)
		return e
	}); err != nil {
		t.Fatalf("insert connector: %v", err)
	}
}

func connectorHealth(t *testing.T, db *database.DB, tid, id uuid.UUID) string {
	t.Helper()
	var h string
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT health FROM connector_configs WHERE id=$1`, id).Scan(&h)
	}); err != nil {
		t.Fatalf("read health: %v", err)
	}
	return h
}

func TestSilenceSweeper_FlagsSilentHostSource(t *testing.T) {
	db := silDB(t)
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "sil-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	silent := uuid.New() // reported 90 min ago → silent
	fresh := uuid.New()  // reported 1 min ago → healthy
	insertHostConnector(t, db, tn.ID, silent, 90)
	insertHostConnector(t, db, tn.ID, fresh, 1)

	al := &mockSilenceAlerter{}
	sw := NewSilenceSweeper(NewRepository(db), al)
	ctx := context.Background()

	if _, err := sw.RunOnce(ctx, 30*time.Minute, 500); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if al.count("connector:"+silent.String()) != 1 {
		t.Fatalf("silent source must be alerted once, got %d", al.count("connector:"+silent.String()))
	}
	if al.count("connector:"+fresh.String()) != 0 {
		t.Fatal("a fresh source must NOT be alerted")
	}
	if connectorHealth(t, db, tn.ID, silent) != "silent" {
		t.Fatal("silent source must be flagged health=silent")
	}
	if connectorHealth(t, db, tn.ID, fresh) != "healthy" {
		t.Fatal("fresh source must stay healthy")
	}

	// Second sweep must NOT re-alert the same silence episode (health=silent filters it out).
	if _, err := sw.RunOnce(ctx, 30*time.Minute, 500); err != nil {
		t.Fatalf("sweep2: %v", err)
	}
	if al.count("connector:"+silent.String()) != 1 {
		t.Fatalf("must not re-alert the same silence episode, got %d", al.count("connector:"+silent.String()))
	}

	// A resume (MarkSuccess) then re-silence is a NEW episode → alerts again.
	if err := NewRepository(db).MarkSuccess(ctx, tn.ID, silent); err != nil {
		t.Fatalf("resume: %v", err)
	}
	insertPastSuccess(t, db, tn.ID, silent, 90) // push last_success back to 90 min ago
	if _, err := sw.RunOnce(ctx, 30*time.Minute, 500); err != nil {
		t.Fatalf("sweep3: %v", err)
	}
	if al.count("connector:"+silent.String()) != 2 {
		t.Fatalf("a fresh silence episode must re-alert, got %d", al.count("connector:"+silent.String()))
	}
}

func insertPastSuccess(t *testing.T, db *database.DB, tid, id uuid.UUID, ageMinutes int) {
	t.Helper()
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE connector_configs SET last_success = now() - make_interval(mins => $2), health='healthy' WHERE id=$1`, id, ageMinutes)
		return e
	}); err != nil {
		t.Fatalf("age success: %v", err)
	}
}
