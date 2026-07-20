package reporting

// §6.13 #188 regulatory breach-report landing round (DB-gated). Adversarial probes:
//   - the report carries the real incident content (id, classification, closure narrative, customer-ack) as a
//     downloadable artifact;
//   - the typed-cell formula-injection defense flows through the breach report: an incident whose title is a
//     spreadsheet formula is neutralized in CSV (never emitted as a live formula);
//   - fail-closed when no incident reader is configured (never an empty/misleading artifact);
//   - a foreign-tenant / unknown incident id resolves to not-found via the RLS-confined read AND leaves NO orphan
//     'running' report row (the incident is read before any record is created).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// breachTestReader mirrors the main.go adapter — reads the incident under RLS via the real incident.Service (Get
// touches only the repo + pure breach computation, so nil alert/notify deps are safe) and projects it into the
// reporting shape. Using the real service proves the tenant isolation, not a stub.
type breachTestReader struct{ inc *incident.Service }

func (a breachTestReader) BreachIncident(ctx context.Context, tenantID, incidentID uuid.UUID) (BreachIncident, error) {
	i, err := a.inc.Get(ctx, tenantID, incidentID)
	if err != nil {
		return BreachIncident{}, err
	}
	return BreachIncident{
		ID: i.ID, Title: i.Title, Severity: i.Severity, Category: i.Category, Stage: string(i.Stage),
		CreatedAt: i.CreatedAt, AcknowledgedAt: i.AcknowledgedAt, ClosedAt: i.ClosedAt,
		Disposition: i.Disposition, RootCause: i.RootCause, Impact: i.Impact, ActionsTaken: i.ActionsTaken,
		LessonsLearned: i.LessonsLearned, CustomerAck: i.CustomerAck,
	}, nil
}

func repSvcBreach(t *testing.T, db *database.DB) *ReportService {
	t.Helper()
	blobs, err := blobstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("blobstore: %v", err)
	}
	inc := incident.NewService(incident.NewRepository(db), nil, nil)
	return NewReportService(NewReportRepository(db), blobs, NewService(db, eventstore.NewPostgres(db))).
		WithBreachSource(breachTestReader{inc: inc})
}

// seedBreachIncident inserts a CLOSED incident with a full closure narrative and returns its id. The title is
// caller-controlled so a formula payload can be injected.
func seedBreachIncident(t *testing.T, db *database.DB, tid uuid.UUID, title string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	created := time.Now().Add(-2 * time.Hour)
	ack := created.Add(10 * time.Minute)
	closed := created.Add(90 * time.Minute)
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, title, severity, category, stage, created_at,
			                        acknowledged_at, closed_at, disposition, root_cause, impact,
			                        actions_taken, lessons_learned, customer_ack)
			 VALUES ($1,$2,$3,'high','identity','closed',$4,$5,$6,'true_positive','phished cred',
			         'one mailbox','isolated + reset','enforce MFA',true)`,
			id, tid, title, created, ack, closed)
		return e
	}); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	return id
}

// The breach report generates ready, is downloadable, and carries the incident content.
func TestBreachReport_GenerateContainsIncident(t *testing.T) {
	db := repDB(t)
	tid := repTenant(t, db)
	svc := repSvcBreach(t, db)
	ctx := context.Background()

	incID := seedBreachIncident(t, db, tid, "unauthorized access")
	author := repActor(tid)
	rep, err := svc.GenerateBreachReport(ctx, author, incID, FormatCSV)
	if err != nil {
		t.Fatalf("generate breach: %v", err)
	}
	if rep.Type != "breach_report" || rep.Status != "ready" || rep.RowCount < 1 {
		t.Fatalf("breach report should be ready with content: %+v", rep)
	}
	// #173: breach_report is review-required (seeded) — it is not releasable until a distinct senior approves it.
	if rep.ReviewStatus != "pending_review" {
		t.Fatalf("a breach report must land pending_review, got %q", rep.ReviewStatus)
	}
	if _, err := svc.Approve(ctx, managerActor(tid), rep.ID); err != nil {
		t.Fatalf("approve breach report: %v", err)
	}
	data, format, err := svc.Download(ctx, author, rep.ID)
	if err != nil || format != FormatCSV {
		t.Fatalf("download: err=%v format=%s", err, format)
	}
	csv := string(data)
	for _, want := range []string{incID.String(), "unauthorized access", "identity", "true_positive", "customer_acknowledged"} {
		if !strings.Contains(csv, want) {
			t.Fatalf("breach CSV missing %q:\n%s", want, csv)
		}
	}
}

// The typed-cell formula-injection defense flows through the breach report: a formula title is neutralized in CSV.
func TestBreachReport_FormulaTitleNeutralized(t *testing.T) {
	db := repDB(t)
	tid := repTenant(t, db)
	svc := repSvcBreach(t, db)
	ctx := context.Background()

	incID := seedBreachIncident(t, db, tid, "=1+2")
	author := repActor(tid)
	rep, err := svc.GenerateBreachReport(ctx, author, incID, FormatCSV)
	if err != nil {
		t.Fatalf("generate breach: %v", err)
	}
	// #173: review-required → approve (distinct senior) before it can be released.
	if _, err := svc.Approve(ctx, managerActor(tid), rep.ID); err != nil {
		t.Fatalf("approve breach report: %v", err)
	}
	data, _, err := svc.Download(ctx, author, rep.ID)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	csv := string(data)
	// Neutralized form present (single-quote prefix); un-neutralized live formula absent at the field boundary.
	if !strings.Contains(csv, "title,'=1+2") {
		t.Fatalf("formula title must be neutralized (quote-prefixed) in CSV:\n%s", csv)
	}
	if strings.Contains(csv, "title,=1+2") {
		t.Fatalf("un-neutralized live formula leaked into CSV:\n%s", csv)
	}
}

// Fail closed: with no incident reader configured, breach reports are refused (never an empty artifact).
func TestBreachReport_NotConfigured(t *testing.T) {
	db := repDB(t)
	tid := repTenant(t, db)
	// repSvc (from report_integration_test.go) has NO breach source wired.
	svc := repSvc(t, db)
	if _, err := svc.GenerateBreachReport(context.Background(), repActor(tid), uuid.New(), FormatCSV); err == nil {
		t.Fatal("breach report with no reader configured must fail closed")
	}
}

// A foreign-tenant / unknown incident id → not-found, and NO orphan report row is created (read-before-create).
func TestBreachReport_ForeignIncidentNotFoundNoOrphan(t *testing.T) {
	db := repDB(t)
	a := repTenant(t, db)
	b := repTenant(t, db)
	svc := repSvcBreach(t, db)
	ctx := context.Background()

	incID := seedBreachIncident(t, db, a, "tenant A only")
	// Tenant B session with tenant A's incident id → RLS-confined read → not-found.
	if _, err := svc.GenerateBreachReport(ctx, repActor(b), incID, FormatJSON); err == nil {
		t.Fatal("a different-tenant session must NOT breach-report another tenant's incident (RLS)")
	}
	// No orphan 'running' breach_report row was created for tenant B.
	var n int
	if err := db.WithTenant(ctx, b, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM reports WHERE tenant_id=$1 AND type='breach_report'`, b).Scan(&n)
	}); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("a rejected foreign-incident breach must leave no report row; got %d", n)
	}
	// The owning tenant still generates fine.
	if _, err := svc.GenerateBreachReport(ctx, repActor(a), incID, FormatJSON); err != nil {
		t.Fatalf("owning tenant must generate its own breach report: %v", err)
	}
}
