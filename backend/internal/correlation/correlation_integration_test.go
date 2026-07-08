package correlation_test

// Correlation clustering against a migrated Postgres. Gated on NIRVET_TEST_DATABASE_URL.

import (
	"context"
	"os"
	"testing"

	"github.com/ArowuTest/nirvet/internal/correlation"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

func TestCorrelation_ClustersByEntity(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run correlation integration tests")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "corr-" + uuid.NewString()})
	svc := correlation.NewService(correlation.NewRepository(db))
	host := "host:" + uuid.NewString()

	// First alert on the host opens a cluster.
	cid1, risk1, err := svc.Correlate(ctx, tn.ID, host, "high", []string{"T1059"}, 50)
	if err != nil || cid1 == uuid.Nil || risk1 <= 0 {
		t.Fatalf("first correlate: cid=%v risk=%d err=%v", cid1, risk1, err)
	}

	// A second alert on the SAME host joins the SAME cluster and escalates it.
	cid2, _, err := svc.Correlate(ctx, tn.ID, host, "critical", []string{"T1486"}, 90)
	if err != nil {
		t.Fatalf("second correlate: %v", err)
	}
	if cid2 != cid1 {
		t.Fatalf("same entity must share a cluster: %v != %v", cid2, cid1)
	}

	got, err := svc.Get(ctx, tn.ID, cid1)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AlertCount != 2 {
		t.Fatalf("cluster should have 2 alerts, got %d", got.AlertCount)
	}
	if got.MaxSeverity != "critical" {
		t.Fatalf("cluster max severity should escalate to critical, got %q", got.MaxSeverity)
	}
	if len(got.Techniques) != 2 {
		t.Fatalf("cluster should union techniques (T1059,T1486), got %v", got.Techniques)
	}
	// Risk rose from a single high-severity alert to a busy critical cluster.
	if got.RiskScore <= risk1 {
		t.Fatalf("cluster risk (%d) should exceed the first alert's risk (%d)", got.RiskScore, risk1)
	}

	// A different host is a different cluster.
	cidOther, _, _ := svc.Correlate(ctx, tn.ID, "host:"+uuid.NewString(), "low", []string{"T1"}, 10)
	if cidOther == cid1 {
		t.Fatal("a different entity must not join the same cluster")
	}

	// No entity → no cluster, but still an individual risk score.
	cidNone, riskNone, _ := svc.Correlate(ctx, tn.ID, "", "high", []string{"T1"}, 50)
	if cidNone != uuid.Nil || riskNone <= 0 {
		t.Fatalf("no-entity alert should not cluster but still score: cid=%v risk=%d", cidNone, riskNone)
	}

	// The list is risk-ranked; the critical cluster ranks above the low one.
	list, _ := svc.List(ctx, tn.ID, "open")
	if len(list) < 2 || list[0].RiskScore < list[len(list)-1].RiskScore {
		t.Fatalf("list must be risk-ranked desc: %+v", list)
	}
}
