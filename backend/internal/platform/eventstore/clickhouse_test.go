package eventstore_test

// ClickHouse EventStore integration test against a real instance. Gated on
// NIRVET_CLICKHOUSE_DSN so it runs where ClickHouse is available and skips otherwise.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/google/uuid"
)

func ev(tenant uuid.UUID, dedupe, sev, class, actor string) eventstore.NormalizedEvent {
	now := time.Now()
	return eventstore.NormalizedEvent{
		ID: uuid.New(), TenantID: tenant, DedupeKey: dedupe, Source: "itest",
		CollectedAt: now, ObservedAt: now, ClassName: class, Severity: sev,
		ActorRef: actor, Confidence: 50, Data: map[string]any{"k": "v"},
	}
}

func TestClickHouseEventStore(t *testing.T) {
	dsn := os.Getenv("NIRVET_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("set NIRVET_CLICKHOUSE_DSN to run ClickHouse tests")
	}
	ctx := context.Background()
	store, err := eventstore.NewClickHouse(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	tenantA := uuid.New()
	tenantB := uuid.New()

	t.Run("AppendIdempotentOnDedupeKey", func(t *testing.T) {
		dk := "ch-" + uuid.NewString()
		e := ev(tenantA, dk, "high", "Malware", "user:a")
		n, err := store.Append(ctx, tenantA, []eventstore.NormalizedEvent{e})
		if err != nil || n != 1 {
			t.Fatalf("first append: n=%d err=%v", n, err)
		}
		// Same dedupe key again → 0 newly inserted.
		n2, err := store.Append(ctx, tenantA, []eventstore.NormalizedEvent{e})
		if err != nil || n2 != 0 {
			t.Fatalf("duplicate append should insert 0: n=%d err=%v", n2, err)
		}
		// A batch mixing the dup + a new key inserts only the new one.
		n3, err := store.Append(ctx, tenantA, []eventstore.NormalizedEvent{e, ev(tenantA, dk+"-2", "low", "Recon", "user:a")})
		if err != nil || n3 != 1 {
			t.Fatalf("mixed batch should insert 1: n=%d err=%v", n3, err)
		}
	})

	t.Run("TenantIsolationOnQuery", func(t *testing.T) {
		dkA := "iso-A-" + uuid.NewString()
		dkB := "iso-B-" + uuid.NewString()
		if _, err := store.Append(ctx, tenantA, []eventstore.NormalizedEvent{ev(tenantA, dkA, "high", "SecretA", "user:a")}); err != nil {
			t.Fatalf("append A: %v", err)
		}
		if _, err := store.Append(ctx, tenantB, []eventstore.NormalizedEvent{ev(tenantB, dkB, "high", "SecretB", "user:b")}); err != nil {
			t.Fatalf("append B: %v", err)
		}
		// Tenant A must never see tenant B's event.
		aRows, err := store.Query(ctx, tenantA, eventstore.Query{Search: "Secret", Limit: 100})
		if err != nil {
			t.Fatalf("query A: %v", err)
		}
		for _, r := range aRows {
			if r.TenantID == tenantB || r.ClassName == "SecretB" {
				t.Fatalf("TENANT LEAK: tenant A saw tenant B's event %+v", r)
			}
		}
		// And tenant A does see its own.
		var sawA bool
		for _, r := range aRows {
			if r.ClassName == "SecretA" {
				sawA = true
			}
		}
		if !sawA {
			t.Fatal("tenant A should see its own event")
		}
	})

	t.Run("QueryFilters", func(t *testing.T) {
		tc := uuid.New()
		_, _ = store.Append(ctx, tc, []eventstore.NormalizedEvent{
			ev(tc, "f-crit-"+uuid.NewString(), "critical", "RansomwareX", "user:c"),
			ev(tc, "f-low-"+uuid.NewString(), "low", "Heartbeat", "user:c"),
		})
		crit, err := store.Query(ctx, tc, eventstore.Query{Severity: "critical", Limit: 50})
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(crit) == 0 {
			t.Fatal("expected the critical event")
		}
		for _, r := range crit {
			if r.Severity != "critical" {
				t.Fatalf("severity filter leaked a %q event", r.Severity)
			}
		}
	})
}
