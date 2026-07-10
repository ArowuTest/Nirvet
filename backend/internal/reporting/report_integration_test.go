package reporting

// §6.13 #125 R-1/R-2/R-4/R-5 integration — generation + session-authorized download + audit + tenant isolation +
// cap enforcement. The headline reviewer probes: download another tenant's report (RLS-confined → not-found), and
// exceed the row/cell ceiling (refused before store).

import (
	"context"
	"strings"
	"testing"

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

// safeFilename strips CR/LF so a Content-Disposition header can't be injected (refinement #4).
func TestSafeFilename_StripsCRLF(t *testing.T) {
	got := safeFilename("report\r\nSet-Cookie: x.csv")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("safeFilename must strip CR/LF: %q", got)
	}
}
