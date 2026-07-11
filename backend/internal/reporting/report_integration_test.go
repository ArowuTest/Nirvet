package reporting

// §6.13 #125 R-1/R-2/R-4/R-5 integration — generation + session-authorized download + audit + tenant isolation +
// cap enforcement. The headline reviewer probes: download another tenant's report (RLS-confined → not-found), and
// exceed the row/cell ceiling (refused before store).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func repDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func repTenant(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "rep-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return tn.ID
}

func repSvc(t *testing.T, db *database.DB) *ReportService {
	t.Helper()
	blobs, err := blobstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("blobstore: %v", err)
	}
	return NewReportService(NewReportRepository(db), blobs, NewService(db, eventstore.NewPostgres(db)))
}

func repActor(tid uuid.UUID) auth.Principal {
	return auth.Principal{UserID: uuid.New(), TenantID: tid, Role: auth.RoleAnalystT1, Email: "a@rep"}
}

// Generate → ready + downloadable; generate & download both audited.
func TestReport_GenerateDownloadAudit(t *testing.T) {
	db := repDB(t)
	tid := repTenant(t, db)
	svc := repSvc(t, db)
	ctx := context.Background()

	rep, err := svc.Generate(ctx, repActor(tid), "service_review", FormatCSV)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if rep.Status != "ready" || rep.RowCount < 1 || rep.ByteSize < 1 {
		t.Fatalf("report should be ready with content: %+v", rep)
	}
	data, format, err := svc.Download(ctx, repActor(tid), rep.ID)
	if err != nil || format != FormatCSV || len(data) == 0 {
		t.Fatalf("download: err=%v format=%s len=%d", err, format, len(data))
	}
	if !strings.Contains(string(data), "metric") {
		t.Fatalf("CSV should contain the header row: %s", string(data))
	}
	var gen, dl int
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM report_audit WHERE tenant_id=$1 AND action='generate'`, tid).Scan(&gen); e != nil {
			return e
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM report_audit WHERE tenant_id=$1 AND action='download'`, tid).Scan(&dl)
	}); err != nil {
		t.Fatalf("audit read: %v", err)
	}
	if gen != 1 || dl != 1 {
		t.Fatalf("REP-008: expected 1 generate + 1 download audit row, got gen=%d dl=%d", gen, dl)
	}
}

// PDF export: Generate(pdf) → ready + downloadable as application/pdf with a valid %PDF header (launch-line, heavy).
func TestReport_GeneratePDF(t *testing.T) {
	db := repDB(t)
	tid := repTenant(t, db)
	svc := repSvc(t, db)
	ctx := context.Background()

	rep, err := svc.Generate(ctx, repActor(tid), "service_review", FormatPDF)
	if err != nil {
		t.Fatalf("generate pdf: %v", err)
	}
	if rep.Status != "ready" || rep.Format != FormatPDF || rep.ByteSize < 1 {
		t.Fatalf("pdf report should be ready with content: %+v", rep)
	}
	data, format, err := svc.Download(ctx, repActor(tid), rep.ID)
	if err != nil || format != FormatPDF {
		t.Fatalf("download pdf: err=%v format=%s", err, format)
	}
	if !strings.HasPrefix(string(data), "%PDF-") {
		t.Fatalf("downloaded artifact must be a PDF (missing %%PDF- header)")
	}
	if FormatPDF.ContentType() != "application/pdf" {
		t.Fatalf("pdf content-type: %s", FormatPDF.ContentType())
	}
}

// Reviewer probe: a report is NOT a bearer capability — tenant B cannot download tenant A's report id.
func TestReport_DownloadTenantIsolation(t *testing.T) {
	db := repDB(t)
	a := repTenant(t, db)
	b := repTenant(t, db)
	svc := repSvc(t, db)
	ctx := context.Background()

	rep, err := svc.Generate(ctx, repActor(a), "service_review", FormatJSON)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// Tenant B session with tenant A's report id → RLS-confined → not-found.
	if _, _, err := svc.Download(ctx, repActor(b), rep.ID); err == nil {
		t.Fatal("a different-tenant session must NOT download another tenant's report (RLS)")
	}
	// The owning tenant still downloads fine.
	if _, _, err := svc.Download(ctx, repActor(a), rep.ID); err != nil {
		t.Fatalf("the owning tenant must download its own report: %v", err)
	}
}

// Reviewer probe: exceed the row/cell ceiling → refused before store (caps pinned via the config seam).
func TestReport_CapEnforced(t *testing.T) {
	db := repDB(t)
	tid := repTenant(t, db)
	svc := repSvc(t, db).WithLimits(Limits{MaxRows: 1, MaxCells: 1, MaxBytes: 10})
	if _, err := svc.Generate(context.Background(), repActor(tid), "service_review", FormatCSV); err == nil {
		t.Fatal("a report exceeding the row ceiling must be refused")
	}
}

// seedIncidentTimes inserts an incident with explicit created/acknowledged/closed timestamps so the mean-time
// KPIs can be asserted deterministically. ack/closed may be nil (an open or unacknowledged incident).
func seedIncidentTimes(t *testing.T, db *database.DB, tid uuid.UUID, created time.Time, ack, closed *time.Time) {
	t.Helper()
	stage := "investigating"
	if closed != nil {
		stage = "closed"
	}
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, title, severity, category, stage, created_at,
			                        acknowledged_at, closed_at, disposition, root_cause, impact, actions_taken)
			 VALUES ($1,$2,$3,'high','',$4,$5,$6,$7,$8,$9,$10,$11)`,
			uuid.New(), tid, "mt-"+uuid.NewString(), stage, created, ack, closed,
			"true_positive", "rc", "impact", "actions")
		return e
	}); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
}

// MTTA/MTTR are the mean of (acknowledged_at−created_at) and (closed_at−created_at) over in-window incidents;
// out-of-window and open incidents are excluded; an empty sample yields nil (never a misleading 0).
func TestMeanTimes_MTTA_MTTR(t *testing.T) {
	db := repDB(t)
	tid := repTenant(t, db)
	ctx := context.Background()
	content := NewService(db, eventstore.NewPostgres(db))

	// No incidents yet → both means nil, sample counts 0.
	sum0, err := content.Summary(ctx, tid)
	if err != nil {
		t.Fatalf("summary(empty): %v", err)
	}
	if sum0.MeanTimes.MTTASeconds != nil || sum0.MeanTimes.MTTRSeconds != nil {
		t.Fatalf("empty sample must yield nil means, got %+v", sum0.MeanTimes)
	}
	if sum0.MeanTimes.WindowDays != meanTimeWindowDays {
		t.Fatalf("window_days = %d, want %d", sum0.MeanTimes.WindowDays, meanTimeWindowDays)
	}

	now := time.Now()
	ackAt := func(base time.Time, d time.Duration) *time.Time { v := base.Add(d); return &v }
	// Two in-window, acknowledged + closed: ack deltas 60s/120s → MTTA 90; resolve deltas 3600s/7200s → MTTR 5400.
	c1 := now.Add(-10 * 24 * time.Hour)
	seedIncidentTimes(t, db, tid, c1, ackAt(c1, 60*time.Second), ackAt(c1, 3600*time.Second))
	c2 := now.Add(-5 * 24 * time.Hour)
	seedIncidentTimes(t, db, tid, c2, ackAt(c2, 120*time.Second), ackAt(c2, 7200*time.Second))
	// Out-of-window (60d ago): must be excluded from both means.
	c3 := now.Add(-60 * 24 * time.Hour)
	seedIncidentTimes(t, db, tid, c3, ackAt(c3, 999*time.Second), ackAt(c3, 999*time.Second))
	// Open + unacknowledged, in-window: contributes to neither.
	seedIncidentTimes(t, db, tid, now.Add(-1*24*time.Hour), nil, nil)

	sum, err := content.Summary(ctx, tid)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	mt := sum.MeanTimes
	if mt.AcknowledgedCount != 2 || mt.ResolvedCount != 2 {
		t.Fatalf("sample counts: acked=%d resolved=%d, want 2/2", mt.AcknowledgedCount, mt.ResolvedCount)
	}
	if mt.MTTASeconds == nil || mt.MTTRSeconds == nil {
		t.Fatalf("means must be present: %+v", mt)
	}
	if *mt.MTTASeconds < 89.9 || *mt.MTTASeconds > 90.1 {
		t.Fatalf("MTTA = %.3f, want ~90", *mt.MTTASeconds)
	}
	if *mt.MTTRSeconds < 5399.9 || *mt.MTTRSeconds > 5400.1 {
		t.Fatalf("MTTR = %.3f, want ~5400", *mt.MTTRSeconds)
	}
}

// safeFilename strips CR/LF so a Content-Disposition header can't be injected (refinement #4).
func TestSafeFilename_StripsCRLF(t *testing.T) {
	got := safeFilename("report\r\nSet-Cookie: x.csv")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("safeFilename must strip CR/LF: %q", got)
	}
}
