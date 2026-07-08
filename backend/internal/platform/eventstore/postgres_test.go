package eventstore_test

// Postgres EventStore round-trip, gated on NIRVET_TEST_DATABASE_URL. Verifies the
// append/query column lists stay in sync (a SELECT/scan mismatch is a runtime, not
// compile, error) and that schema_version round-trips (ADR-0006).

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

func TestPostgresEventStoreRoundTrip(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run the Postgres event store test")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "es-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	store := eventstore.NewPostgres(db)

	dk := "pg-es-" + uuid.NewString()
	now := time.Now()
	e := eventstore.NormalizedEvent{
		ID: uuid.New(), TenantID: tn.ID, DedupeKey: dk, Source: "itest",
		CollectedAt: now, ObservedAt: now, ClassName: "MalwareRoundTrip", Severity: "high",
		ActorRef: "user:a", Confidence: 42, Data: map[string]any{"k": "v"},
		// SchemaVersion intentionally left empty -> Append must default it.
	}
	n, err := store.Append(ctx, tn.ID, []eventstore.NormalizedEvent{e})
	if err != nil || n != 1 {
		t.Fatalf("append: n=%d err=%v", n, err)
	}
	// Duplicate -> 0 newly inserted (idempotent).
	if n2, _ := store.Append(ctx, tn.ID, []eventstore.NormalizedEvent{e}); n2 != 0 {
		t.Fatalf("duplicate append should insert 0, got %d", n2)
	}

	got, err := store.Query(ctx, tn.ID, eventstore.Query{Search: "MalwareRoundTrip", Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected the appended event back")
	}
	if got[0].SchemaVersion != eventstore.CanonicalSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", got[0].SchemaVersion, eventstore.CanonicalSchemaVersion)
	}
	if got[0].Confidence != 42 || got[0].ClassName != "MalwareRoundTrip" {
		t.Fatalf("round-trip mismatch: %+v", got[0])
	}
}
