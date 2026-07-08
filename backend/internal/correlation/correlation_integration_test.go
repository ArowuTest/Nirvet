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
	"github.com/jackc/pgx/v5"
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

// TestCorrelation_SuppressionStormMetrics covers §6.7 slice C: suppression withholds auto-promotion
// (COR-007), storm status trips at the configured threshold (COR-008), and over-correlation metrics
// compute (COR-010).
func TestCorrelation_SuppressionStormMetrics(t *testing.T) {
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
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "corr-sup-" + uuid.NewString()})

	inc := &stubIncidenter{}
	svc := correlation.NewService(correlation.NewRepository(db)).WithIncidenter(inc)

	// COR-007: suppress a specific entity, then send a corroborated high-risk cluster on it → the
	// cluster is formed and flagged suppressed, but NO incident is auto-opened.
	suppressed := "host:" + uuid.NewString()
	if _, err := svc.CreateSuppression(ctx, tn.ID, uuid.New(), correlation.SuppressionInput{
		MatchType: "entity", MatchValue: suppressed, Reason: "planned maintenance",
	}); err != nil {
		t.Fatalf("create suppression: %v", err)
	}
	cid, _, _ := svc.Correlate(ctx, tn.ID, suppressed, "critical", []string{"T1486", "T1490"}, 95)
	if _, _, err := svc.Correlate(ctx, tn.ID, suppressed, "critical", []string{"T1059"}, 95); err != nil {
		t.Fatalf("correlate suppressed: %v", err)
	}
	if inc.opened != 0 {
		t.Fatalf("a suppressed entity must not auto-open an incident, opened=%d", inc.opened)
	}
	sc, _ := svc.Get(ctx, tn.ID, cid)
	if !sc.Suppressed || sc.SuppressionReason == "" {
		t.Fatalf("cluster should be flagged suppressed with a reason: %+v", sc)
	}

	// Control: a non-suppressed entity DOES auto-open (proves suppression, not a broken promoter).
	other := "host:" + uuid.NewString()
	svc.Correlate(ctx, tn.ID, other, "critical", []string{"T1486", "T1490"}, 95)
	svc.Correlate(ctx, tn.ID, other, "critical", []string{"T1059"}, 95)
	if inc.opened != 1 {
		t.Fatalf("a non-suppressed corroborated cluster should promote, opened=%d", inc.opened)
	}

	// Delete the suppression.
	sups, _ := svc.ListSuppressions(ctx, tn.ID)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if err := svc.DeleteSuppression(ctx, tn.ID, sups[0].ID); err != nil {
		t.Fatalf("delete suppression: %v", err)
	}

	// COR-008: lower the storm threshold for this tenant, then confirm InStorm trips.
	if err := db.WithTenant(ctx, tn.ID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO correlation_policies (tenant_id, storm_cluster_threshold) VALUES ($1, 5)
			 ON CONFLICT (tenant_id) DO UPDATE SET storm_cluster_threshold = 5`, tn.ID)
		return e
	}); err != nil {
		t.Fatalf("set storm threshold: %v", err)
	}
	// Open several more PROMOTABLE clusters (2 corroborating alerts each, so alert_count>=2) so the
	// last-hour count clears the threshold of 5. Single-alert clusters no longer count toward storm
	// (R5-H4), so each entity gets two low-severity alerts (still below the promote threshold).
	for i := 0; i < 5; i++ {
		e := "host:" + uuid.NewString()
		svc.Correlate(ctx, tn.ID, e, "low", []string{"T1"}, 10)
		svc.Correlate(ctx, tn.ID, e, "low", []string{"T1"}, 10)
	}
	st, err := svc.Storm(ctx, tn.ID)
	if err != nil {
		t.Fatalf("storm: %v", err)
	}
	if st.Threshold != 5 {
		t.Fatalf("storm threshold should be 5, got %d", st.Threshold)
	}
	if !st.InStorm {
		t.Fatalf("expected storm mode with %d clusters >= threshold %d", st.ClustersLastHour, st.Threshold)
	}

	// R5-H4 during storm: a non-critical corroborated cluster is WITHHELD and visibly flagged
	// (suppressed + reason), NOT silently dropped.
	openedBefore := inc.opened
	hi := "host:" + uuid.NewString()
	// Three alerts so the aggregate risk clears the promote threshold (else it wouldn't promote anyway).
	svc.Correlate(ctx, tn.ID, hi, "high", []string{"T1486", "T1490"}, 95)
	svc.Correlate(ctx, tn.ID, hi, "high", []string{"T1059"}, 95)
	hiID, _, _ := svc.Correlate(ctx, tn.ID, hi, "high", []string{"T1071"}, 95)
	if inc.opened != openedBefore {
		t.Fatal("a non-critical cluster must be withheld under storm")
	}
	hc, _ := svc.Get(ctx, tn.ID, hiID)
	if !hc.Suppressed || hc.SuppressionReason == "" {
		t.Fatalf("storm-withheld cluster must be flagged visibly: %+v", hc)
	}
	// A CRITICAL cluster must break through storm and still auto-open an incident.
	crit := "host:" + uuid.NewString()
	svc.Correlate(ctx, tn.ID, crit, "critical", []string{"T1486", "T1490"}, 95)
	svc.Correlate(ctx, tn.ID, crit, "critical", []string{"T1059"}, 95)
	if inc.opened != openedBefore+1 {
		t.Fatalf("a critical cluster must break through storm mode, opened=%d want=%d", inc.opened, openedBefore+1)
	}

	// COR-010: over-correlation metrics are populated.
	m, err := svc.OverCorrelation(ctx, tn.ID)
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	if m.Clusters == 0 || m.TotalAlerts == 0 || m.AlertsPerCluster <= 0 || m.LargestCluster < 2 {
		t.Fatalf("over-correlation metrics look wrong: %+v", m)
	}
}
