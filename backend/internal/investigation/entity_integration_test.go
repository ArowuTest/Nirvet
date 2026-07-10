package investigation

// §6.9 #124 I-3 integration — typed entity profile + pivot over the real (tenant-scoped) entity graph. The headline
// is the reviewer's pivot concern: a pivot neighbor is derived from the tenant's OWN alerts, so it can never reach a
// cross-tenant entity even when both tenants share the same center ref.

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/correlation"
	"github.com/ArowuTest/nirvet/internal/entitygraph"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Minimal fakes for the graph deps the pivot does not exercise (incidents/correlations/assets); the alert reader is
// real so RLS tenant isolation is genuinely tested.
type fakeIncidents struct{}

func (fakeIncidents) GetByIDs(context.Context, uuid.UUID, []uuid.UUID) ([]incident.Incident, error) {
	return nil, nil
}

type fakeCorrs struct{}

func (fakeCorrs) ListByEntity(context.Context, uuid.UUID, string) ([]correlation.Correlation, error) {
	return nil, nil
}

type fakeAssets struct{}

func (fakeAssets) FindByRefs(context.Context, uuid.UUID, []string) ([]asset.Asset, error) {
	return nil, nil
}

func entitySvc(db *database.DB) *EntityService {
	eg := entitygraph.NewService(alert.NewService(alert.NewRepository(db)), fakeIncidents{}, fakeCorrs{}, fakeAssets{})
	return NewEntityService(eg, NewRepository(db))
}

func seedAlert(t *testing.T, db *database.DB, tid uuid.UUID, actorRef, targetRef, severity string) {
	t.Helper()
	ev := eventstore.NormalizedEvent{
		ID: uuid.New(), TenantID: tid, DedupeKey: uuid.NewString(), Source: "s",
		ObservedAt: time.Now(), CollectedAt: time.Now(), ClassName: "Process Activity", Severity: severity,
		ActorRef: actorRef, TargetRef: targetRef,
	}
	_, ins, err := alert.NewService(alert.NewRepository(db)).
		CreateFromEvent(context.Background(), ev, alert.Spec{Title: "t", Severity: severity, DedupeKey: ev.DedupeKey + ":a"})
	if err != nil || !ins {
		t.Fatalf("seed alert: ins=%v err=%v", ins, err)
	}
}

// Pivot must not escape the tenant: both tenants share center host:FIN-01, but tenant A only ever sees its own
// neighbor (user:alice), never tenant B's (user:bob).
func TestEntity_PivotTenantIsolation(t *testing.T) {
	db := invDB(t)
	a := invTenant(t, db)
	b := invTenant(t, db)
	seedAlert(t, db, a, "host:FIN-01", "user:alice", "high")
	seedAlert(t, db, b, "host:FIN-01", "user:bob", "high")

	view, err := entitySvc(db).Pivot(context.Background(), analystOf(a), "host:FIN-01")
	if err != nil {
		t.Fatalf("pivot: %v", err)
	}
	if len(view.Neighbors) != 1 {
		t.Fatalf("tenant A pivot must yield exactly its own neighbor, got %d", len(view.Neighbors))
	}
	if view.Neighbors[0].Entity.Ref() != "user:alice" {
		t.Fatalf("cross-tenant pivot leak: got %q (expected user:alice)", view.Neighbors[0].Entity.Ref())
	}
}

// Profile composes the entity graph and records an entity_read audit row (INV-007).
func TestEntity_ProfileAndAudit(t *testing.T) {
	db := invDB(t)
	tid := invTenant(t, db)
	seedAlert(t, db, tid, "host:FIN-01", "user:alice", "high")

	prof, err := entitySvc(db).GetProfile(context.Background(), analystOf(tid), "host:FIN-01")
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if prof.Entity.Kind != "host" || prof.Graph == nil || prof.Graph.Summary.AlertCount < 1 {
		t.Fatalf("profile should compose the entity graph with >=1 alert, got %+v", prof.Entity)
	}
	var n int
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM investigation_query_audit WHERE tenant_id=$1 AND kind='entity_read'`, tid).Scan(&n)
	}); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if n < 1 {
		t.Fatal("an entity read must be recorded in the read-path audit (INV-007)")
	}
}

func TestEntity_UnknownKindRejected(t *testing.T) {
	db := invDB(t)
	tid := invTenant(t, db)
	if _, err := entitySvc(db).GetProfile(context.Background(), analystOf(tid), "secret:x"); err == nil {
		t.Fatal("an unknown entity kind must be rejected")
	}
}
