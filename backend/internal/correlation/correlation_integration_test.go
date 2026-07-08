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
	for i := 1; i < len(list); i++ {
		if list[i-1].EffectiveRisk() < list[i].EffectiveRisk() {
			t.Fatalf("list must be risk-ranked desc: %+v", list)
		}
	}

	// COR-006 explainability: the factor breakdown reconstructs the computed risk from stored signals.
	expC, factors, err := svc.Explain(ctx, tn.ID, cid1)
	if err != nil || len(factors) != 4 {
		t.Fatalf("explain: %d factors err=%v", len(factors), err)
	}
	sum := 0
	for _, f := range factors {
		sum += f.Contribution
	}
	if want := expC.RiskScore; sum < want { // clamp means sum can exceed, never be below the clamped value's inputs
		t.Fatalf("explain factors (%d) below risk score (%d)", sum, want)
	}

	// COR-009 analyst override: reason mandatory; override wins as effective risk/severity.
	if err := svc.Override(ctx, tn.ID, cid1, uuid.New(), correlation.OverrideInput{Severity: "low", Risk: ptr(15)}); err == nil {
		t.Fatal("override without a reason must be rejected")
	}
	rk := 15
	if err := svc.Override(ctx, tn.ID, cid1, uuid.New(), correlation.OverrideInput{Severity: "low", Risk: &rk, Reason: "confirmed benign maintenance"}); err != nil {
		t.Fatalf("override: %v", err)
	}
	after, _ := svc.Get(ctx, tn.ID, cid1)
	if after.EffectiveSeverity() != "low" || after.EffectiveRisk() != 15 || after.OverrideReason == "" {
		t.Fatalf("override should win as effective values: %+v", after)
	}
	// The computed values are preserved underneath the override.
	if after.MaxSeverity != "critical" {
		t.Fatalf("computed max severity must be preserved under override, got %q", after.MaxSeverity)
	}
}

func ptr(i int) *int { return &i }

// stubIncidenter records the incidents a correlation would auto-open.
type stubIncidenter struct{ opened int }

func (s *stubIncidenter) OpenFromCorrelation(_ context.Context, _ uuid.UUID, _, _ string, _ int, _ []string) (uuid.UUID, error) {
	s.opened++
	return uuid.New(), nil
}

func TestCorrelation_AutoPromotesHighRisk(t *testing.T) {
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
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "corr-promo-" + uuid.NewString()})

	inc := &stubIncidenter{}
	svc := correlation.NewService(correlation.NewRepository(db)).WithIncidenter(inc)
	host := "host:" + uuid.NewString()

	// Corroboration (R2 M-A): a SINGLE high-risk alert must NOT auto-open an incident,
	// even above the risk threshold — one crafted event can't spawn a case.
	cid, _, err := svc.Correlate(ctx, tn.ID, host, "critical", []string{"T1486", "T1490", "T1059"}, 90)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if inc.opened != 0 {
		t.Fatalf("a single high-risk alert must NOT auto-open an incident (needs corroboration), got %d", inc.opened)
	}
	// A SECOND corroborating alert on the same entity crosses the corroboration bar →
	// exactly one incident is opened.
	if _, _, err := svc.Correlate(ctx, tn.ID, host, "critical", []string{"T1055"}, 90); err != nil {
		t.Fatalf("second correlate: %v", err)
	}
	if inc.opened != 1 {
		t.Fatalf("a corroborated high-risk cluster should auto-open exactly one incident, got %d", inc.opened)
	}
	got, _ := svc.Get(ctx, tn.ID, cid)
	if got.Status != correlation.StatusPromoted || got.IncidentID == nil {
		t.Fatalf("cluster should be marked promoted with an incident: status=%s incident=%v", got.Status, got.IncidentID)
	}
	// A third alert on the same (now promoted) cluster must NOT open a second incident.
	if _, _, err := svc.Correlate(ctx, tn.ID, host, "critical", []string{"T1071"}, 90); err != nil {
		t.Fatalf("third correlate: %v", err)
	}
	if inc.opened != 1 {
		t.Fatalf("an already-promoted cluster must not re-promote, opened=%d", inc.opened)
	}

	// A low-risk cluster stays open (below threshold) — no incident.
	if _, _, err := svc.Correlate(ctx, tn.ID, "host:"+uuid.NewString(), "low", nil, 0); err != nil {
		t.Fatalf("low correlate: %v", err)
	}
	if inc.opened != 1 {
		t.Fatalf("a low-risk cluster must not promote, opened=%d", inc.opened)
	}
}
