// Package integrationtest exercises the real services end to end against a
// migrated Postgres. Gated on NIRVET_TEST_DATABASE_URL so it runs in CI and
// locally, and skips otherwise. Covers auth/audit, ingestion + alert dedupe,
// detection, incident promotion, connector webhook auth, and SOAR approval gating.
package integrationtest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/connector"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/iam"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/queue"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/ArowuTest/nirvet/internal/threatintel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type harness struct {
	ctx       context.Context
	db        *database.DB
	tenantID  uuid.UUID
	principal auth.Principal
	email     string

	iamSvc   *iam.Service
	ingest   *ingestion.Service
	worker   *ingestion.Worker
	alertSvc *alert.Service
	incSvc   *incident.Service
	connSvc  *connector.Service
	soarSvc  *soar.Service
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run integration tests")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// A real tenant (SOAR reads tenants.authority_mode) + a user.
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "itest-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tokens := auth.NewManager("test-secret", "nirvet", 15*time.Minute)
	iamSvc := iam.NewService(iam.NewRepository(db), db, tokens)
	email := "itest-" + uuid.NewString() + "@t"
	u, err := iamSvc.Create(ctx, tn.ID, iam.CreateInput{Email: email, Password: "password123", Role: auth.RoleAnalystT2})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	principal := auth.Principal{UserID: u.ID, TenantID: tn.ID, Role: auth.RoleAnalystT2, Email: email}

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cipher, _ := crypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	blobs, _ := blobstore.NewLocal(t.TempDir())
	q := queue.NewPostgres(db.Pool)
	events := eventstore.NewPostgres(db)
	alertSvc := alert.NewService(alert.NewRepository(db))
	detEng := detection.NewEngine(detection.NewRepository(db))
	enr := threatintel.NewEnricher(threatintel.NewRepository(db))
	ingestSvc := ingestion.NewService(ingestion.NewRepository(db), q, nil, blobs)

	return &harness{
		ctx: ctx, db: db, tenantID: tn.ID, principal: principal, email: email,
		iamSvc:   iamSvc,
		ingest:   ingestSvc,
		worker:   ingestion.NewWorker(q, events, enr, detEng, alertSvc, log),
		alertSvc: alertSvc,
		incSvc:   incident.NewService(incident.NewRepository(db), alertSvc, nil),
		connSvc:  connector.NewService(connector.NewRepository(db), connector.NewVault(cipher), ingestSvc),
		soarSvc:  soar.NewService(soar.NewRepository(db)),
	}
}

func (h *harness) countRaw(t *testing.T, dedupe string) int {
	var n int
	if err := h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM raw_events WHERE dedupe_key=$1`, dedupe).Scan(&n)
	}); err != nil {
		t.Fatalf("countRaw: %v", err)
	}
	return n
}

func TestIntegration(t *testing.T) {
	h := newHarness(t)

	t.Run("LoginAudit", func(t *testing.T) {
		if _, err := h.iamSvc.Login(h.ctx, h.email, "password123", "req-itest"); err != nil {
			t.Fatalf("login: %v", err)
		}
		if _, err := h.iamSvc.Login(h.ctx, h.email, "wrong", "req-itest"); err == nil {
			t.Fatal("login with wrong password must fail")
		}
		var n int
		_ = h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='auth.login' AND actor_email=$1`, h.email).Scan(&n)
		})
		if n < 1 {
			t.Fatal("expected an auth.login audit record")
		}
	})

	t.Run("IngestDedupeAndDetect", func(t *testing.T) {
		in := ingestion.IngestInput{Source: "itest", NativeID: "e1", ClassName: "Malware xyz", Severity: "critical", ActorRef: "user:x", TargetRef: "host:h1"}
		dk, err := h.ingest.Ingest(h.ctx, h.tenantID, in)
		if err != nil {
			t.Fatalf("ingest 1: %v", err)
		}
		if _, err := h.ingest.Ingest(h.ctx, h.tenantID, in); err != nil { // duplicate
			t.Fatalf("ingest 2: %v", err)
		}
		if got := h.countRaw(t, dk); got != 1 {
			t.Fatalf("raw dedupe failed: %d raw rows, want 1", got)
		}
		if _, err := h.worker.RunOnce(h.ctx); err != nil {
			t.Fatalf("worker: %v", err)
		}
		alerts, _ := h.alertSvc.List(h.ctx, h.tenantID, "")
		before := len(alerts)
		if before == 0 {
			t.Fatal("detection should have raised at least one alert for a malware/critical event")
		}
		// Re-run the worker: no new alerts (idempotent).
		_, _ = h.worker.RunOnce(h.ctx)
		alerts2, _ := h.alertSvc.List(h.ctx, h.tenantID, "")
		if len(alerts2) != before {
			t.Fatalf("worker re-run created duplicate alerts: %d -> %d", before, len(alerts2))
		}
	})

	t.Run("AlertDedupe", func(t *testing.T) {
		ev := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: h.tenantID, Severity: "high", Source: "itest"}
		spec := alert.Spec{Title: "dup", Severity: "high", DedupeKey: ev.ID.String() + ":rule-x"}
		_, ins1, err := h.alertSvc.CreateFromEvent(h.ctx, ev, spec)
		if err != nil || !ins1 {
			t.Fatalf("first alert should insert: ins=%v err=%v", ins1, err)
		}
		_, ins2, err := h.alertSvc.CreateFromEvent(h.ctx, ev, spec)
		if err != nil {
			t.Fatalf("second create err: %v", err)
		}
		if ins2 {
			t.Fatal("second alert with same dedupe key must NOT insert")
		}
	})

	t.Run("IncidentPromotion", func(t *testing.T) {
		alerts, _ := h.alertSvc.List(h.ctx, h.tenantID, "new")
		if len(alerts) == 0 {
			t.Skip("no new alert to promote")
		}
		aID := alerts[0].ID
		inc, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, aID)
		if err != nil {
			t.Fatalf("promote: %v", err)
		}
		got, _ := h.alertSvc.Get(h.ctx, h.tenantID, aID)
		if got.Status != alert.StatusPromoted || got.IncidentID == nil {
			t.Fatalf("alert not marked promoted/linked: status=%s incident=%v", got.Status, got.IncidentID)
		}
		tl, _ := h.incSvc.Timeline(h.ctx, h.tenantID, inc.ID)
		if len(tl) == 0 {
			t.Fatal("incident should have a seed timeline entry")
		}
	})

	t.Run("ConnectorWebhookAuth", func(t *testing.T) {
		res, err := h.connSvc.Create(h.ctx, h.tenantID, connector.CreateInput{Kind: connector.KindWebhook, Name: "wh"})
		if err != nil {
			t.Fatalf("create connector: %v", err)
		}
		events := []ingestion.IngestInput{{Source: "wh", NativeID: "w1", Severity: "low"}}
		if _, err := h.connSvc.IngestWebhook(h.ctx, res.Connector.ID, "wrong-key", events); err == nil {
			t.Fatal("webhook with wrong key must be rejected")
		}
		n, err := h.connSvc.IngestWebhook(h.ctx, res.Connector.ID, res.SourceKey, events)
		if err != nil || n != 1 {
			t.Fatalf("webhook with correct key: n=%d err=%v", n, err)
		}
	})

	t.Run("SOARApprovalGating", func(t *testing.T) {
		pbs, err := h.soarSvc.ListPlaybooks(h.ctx, h.tenantID)
		if err != nil || len(pbs) == 0 {
			t.Fatalf("expected a seeded global playbook: %v", err)
		}
		// Default authority is 'observe' → all containment steps require approval.
		run, err := h.soarSvc.Run(h.ctx, h.principal, pbs[0].ID, nil)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if run.Status != soar.RunPendingApproval {
			t.Fatalf("under 'observe' the run must be pending_approval, got %s", run.Status)
		}
		approved, err := h.soarSvc.Approve(h.ctx, h.principal, run.ID)
		if err != nil {
			t.Fatalf("approve: %v", err)
		}
		if approved.Status != soar.RunCompleted {
			t.Fatalf("after approval the run must be completed, got %s", approved.Status)
		}
	})
}
