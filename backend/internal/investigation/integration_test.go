package investigation

// §6.9 #124 I-1/I-2 integration — the DB-facing guarantees: the compiled query filters correctly, RLS is the
// backstop (a hunt in tenant A can never see tenant B's events), the read-path audit is written one-row-per-execution
// with the returned row count, and the bounded time window excludes out-of-range events.

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func invDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func invTenant(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "inv-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return tn.ID
}

func seedEvent(t *testing.T, db *database.DB, tid uuid.UUID, at time.Time, severity, actorRef, source string) {
	t.Helper()
	_, err := eventstore.NewPostgres(db).Append(context.Background(), tid, []eventstore.NormalizedEvent{{
		ID: uuid.New(), TenantID: tid, DedupeKey: uuid.NewString(), Source: source,
		ObservedAt: at, CollectedAt: at, ClassName: "Process Activity", Severity: severity,
		Confidence: 80, ActorRef: actorRef, TargetRef: "host:FIN-01", Action: "run", Outcome: "success",
		MITRE: []string{"T1059"}, Vendor: "acme", Product: "edr",
	}})
	if err != nil {
		t.Fatalf("seed event: %v", err)
	}
}

func analystOf(tid uuid.UUID) auth.Principal {
	return auth.Principal{UserID: uuid.New(), TenantID: tid, Role: auth.RoleAnalystT1, Email: "a@inv"}
}

func win() (time.Time, time.Time) {
	now := time.Now()
	return now.Add(-time.Hour), now.Add(time.Hour)
}

// RLS backstop: a hunt in tenant A returns only A's events, never B's — even though both match the predicate.
func TestHunt_TenantIsolation(t *testing.T) {
	db := invDB(t)
	a := invTenant(t, db)
	b := invTenant(t, db)
	now := time.Now()
	seedEvent(t, db, a, now, "high", "user:alice", "srcA")
	seedEvent(t, db, b, now, "high", "user:bob", "srcB")

	from, to := win()
	q := HuntQuery{From: from, To: to, All: []Predicate{{Field: "severity", Op: OpEq, Value: "high"}}}
	res, err := NewService(NewRepository(db)).RunHunt(context.Background(), analystOf(a), q)
	if err != nil {
		t.Fatalf("hunt: %v", err)
	}
	if res.Count != 1 {
		t.Fatalf("tenant A must see exactly its own matching event, got %d", res.Count)
	}
	if res.Rows[0].ActorRef != "user:alice" {
		t.Fatalf("RLS leak: tenant A saw %q (expected user:alice only)", res.Rows[0].ActorRef)
	}
}

// The compiled predicate actually filters (severity=high excludes a low event) and the time window excludes an
// out-of-range event.
func TestHunt_PredicateAndWindowFilter(t *testing.T) {
	db := invDB(t)
	tid := invTenant(t, db)
	now := time.Now()
	seedEvent(t, db, tid, now, "high", "user:a", "s")
	seedEvent(t, db, tid, now, "low", "user:b", "s")
	seedEvent(t, db, tid, now.Add(-48*time.Hour), "high", "user:old", "s") // outside the 1h window

	from, to := win()
	q := HuntQuery{From: from, To: to, All: []Predicate{{Field: "severity", Op: OpEq, Value: "high"}}}
	res, err := NewService(NewRepository(db)).RunHunt(context.Background(), analystOf(tid), q)
	if err != nil {
		t.Fatalf("hunt: %v", err)
	}
	if res.Count != 1 || res.Rows[0].ActorRef != "user:a" {
		t.Fatalf("predicate+window must return only the in-window high event, got %d rows", res.Count)
	}
}

// INV-007: the read-path audit records one row per execution with the returned count.
func TestHunt_WritesReadAudit(t *testing.T) {
	db := invDB(t)
	tid := invTenant(t, db)
	now := time.Now()
	seedEvent(t, db, tid, now, "high", "user:a", "s")
	seedEvent(t, db, tid, now, "high", "user:b", "s")

	from, to := win()
	q := HuntQuery{From: from, To: to, All: []Predicate{{Field: "severity", Op: OpEq, Value: "high"}}}
	p := analystOf(tid)
	res, err := NewService(NewRepository(db)).RunHunt(context.Background(), p, q)
	if err != nil {
		t.Fatalf("hunt: %v", err)
	}
	var n, rowCount int
	var actor uuid.UUID
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM investigation_query_audit WHERE tenant_id=$1 AND kind='hunt_query'`, tid).Scan(&n); e != nil {
			return e
		}
		return tx.QueryRow(ctx,
			`SELECT row_count, actor_id FROM investigation_query_audit WHERE tenant_id=$1 AND kind='hunt_query' LIMIT 1`, tid).Scan(&rowCount, &actor)
	}); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("exactly one read-audit row per execution, got %d", n)
	}
	if rowCount != res.Count {
		t.Fatalf("audit row_count %d must match returned count %d", rowCount, res.Count)
	}
	if actor != p.UserID {
		t.Fatal("audit must record the querying actor")
	}
}

// The append-only trail rejects mutation (INV-007 evidence integrity).
func TestReadAudit_AppendOnly(t *testing.T) {
	db := invDB(t)
	tid := invTenant(t, db)
	if err := NewRepository(db).WriteQueryAudit(context.Background(), tid, uuid.New(), "hunt_query", map[string]string{"x": "y"}, 3); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE investigation_query_audit SET row_count=999 WHERE tenant_id=$1`, tid)
		return e
	})
	if err == nil {
		t.Fatal("investigation_query_audit must be append-only (UPDATE must fail)")
	}
}
