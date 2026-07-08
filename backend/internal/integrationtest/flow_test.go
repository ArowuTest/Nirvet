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
	"strings"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/billing"
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
	"github.com/ArowuTest/nirvet/internal/platform/totp"
	"github.com/ArowuTest/nirvet/internal/reporting"
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
	billSvc  *billing.Service
	repSvc   *reporting.Service
}

// stubTicketer stands in for ticketing.Service (no HTTP) so the incident→ITSM
// seam can be asserted deterministically. The real ServiceNow/Jira providers are
// covered by the ticketing package's mock-endpoint tests.
type stubTicketer struct{}

func (stubTicketer) MirrorIncident(_ context.Context, _ uuid.UUID, _, _, _ string) (string, string, error) {
	return "INC-TEST-1", "https://itsm.example/INC-TEST-1", nil
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
	hkey := make([]byte, 32)
	_, _ = rand.Read(hkey)
	hcipher, _ := crypto.NewLocal(base64.StdEncoding.EncodeToString(hkey), nil)
	iamSvc := iam.NewService(iam.NewRepository(db), db, tokens, hcipher)
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
	// The telemetry store is interface-selected: with NIRVET_CLICKHOUSE_DSN set, the
	// WHOLE heartbeat runs on ClickHouse (proving the ADR-0002 backend swap); else
	// Postgres. The system-of-record (tenants/users/alerts/incidents) stays Postgres.
	events, closeEvents, _, esErr := eventstore.New(ctx, os.Getenv("NIRVET_CLICKHOUSE_DSN"), db)
	if esErr != nil {
		t.Fatalf("event store: %v", esErr)
	}
	t.Cleanup(func() { _ = closeEvents() })
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
		incSvc:   incident.NewService(incident.NewRepository(db), alertSvc, nil).WithAssignees(iamSvc).WithTicketer(stubTicketer{}),
		connSvc:  connector.NewService(connector.NewRepository(db), connector.NewVault(cipher), ingestSvc),
		soarSvc:  soar.NewService(soar.NewRepository(db)),
		billSvc:  billing.NewService(billing.NewRepository(db)),
		repSvc:   reporting.NewService(db, events),
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
		if _, err := h.iamSvc.Login(h.ctx, h.email, "password123", "", "req-itest"); err != nil {
			t.Fatalf("login: %v", err)
		}
		if _, err := h.iamSvc.Login(h.ctx, h.email, "wrong", "", "req-itest"); err == nil {
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

	// Heartbeat is the platform's "walking skeleton": a single thread pulled through
	// EVERY layer of the SOC value loop, in order, in one test — the owner's chain:
	//   Login → Tenant → Connector → Receive event → Normalize → Store → Detection →
	//   Alert → Incident → Assign analyst → Timeline → Playbook → Close → Audit trail.
	// If this stays green, the architecture has a real heartbeat and everything else
	// (more connectors, AI, dashboards) is incremental. A break here is a P0.
	t.Run("Heartbeat_EndToEnd", func(t *testing.T) {
		// 1. Login (real auth, produces an audit record).
		if _, err := h.iamSvc.Login(h.ctx, h.email, "password123", "", "req-heartbeat"); err != nil {
			t.Fatalf("1. login: %v", err)
		}

		// 2. Tenant + 3. Connector: a webhook connector owned by this tenant.
		conn, err := h.connSvc.Create(h.ctx, h.tenantID, connector.CreateInput{Kind: connector.KindWebhook, Name: "heartbeat-edr"})
		if err != nil {
			t.Fatalf("3. create connector: %v", err)
		}

		// 4. Receive event: push a critical malware event THROUGH the connector
		//    (source-key authenticated), exactly as a real EDR webhook would.
		nativeID := "hb-" + uuid.NewString()
		evts := []ingestion.IngestInput{{
			Source: "heartbeat-edr", NativeID: nativeID, ClassName: "Malware Trojan:Win32/Heartbeat",
			Severity: "critical", ActorRef: "user:cfo", TargetRef: "host:FIN-LAPTOP-01",
		}}
		n, err := h.connSvc.IngestWebhook(h.ctx, conn.Connector.ID, conn.SourceKey, evts)
		if err != nil || n != 1 {
			t.Fatalf("4. connector receive: n=%d err=%v", n, err)
		}

		// 5. Normalize + 6. Store + 7. Detection + 8. Alert: the worker drains the
		//    queue (normalize → event store → detection engine → raise alert).
		if _, err := h.worker.RunOnce(h.ctx); err != nil {
			t.Fatalf("5-8. worker (normalize/store/detect/alert): %v", err)
		}
		alerts, _ := h.alertSvc.List(h.ctx, h.tenantID, "new")
		var hbAlert *alert.Alert
		for i := range alerts {
			if alerts[i].Source == "heartbeat-edr" {
				hbAlert = &alerts[i]
				break
			}
		}
		if hbAlert == nil {
			t.Fatal("8. detection did not raise an alert for a critical malware event from the connector")
		}

		// 9. Incident: promote the alert (atomic; links alert→incident; seeds timeline).
		inc, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, hbAlert.ID)
		if err != nil {
			t.Fatalf("9. promote to incident: %v", err)
		}
		promoted, _ := h.alertSvc.Get(h.ctx, h.tenantID, hbAlert.ID)
		if promoted.Status != alert.StatusPromoted || promoted.IncidentID == nil {
			t.Fatalf("9. alert not linked to incident: status=%s incident=%v", promoted.Status, promoted.IncidentID)
		}

		// 10. Assign analyst: hand the case to a (same-tenant) analyst; case advances.
		if err := h.incSvc.Assign(h.ctx, h.principal, inc.ID, h.principal.UserID); err != nil {
			t.Fatalf("10. assign analyst: %v", err)
		}
		reloaded, _ := h.incSvc.Get(h.ctx, h.tenantID, inc.ID)
		if reloaded.OwnerID == nil || *reloaded.OwnerID != h.principal.UserID {
			t.Fatalf("10. incident owner not set to analyst: %v", reloaded.OwnerID)
		}
		if reloaded.Stage != incident.StageInvestigating {
			t.Fatalf("10. incident should move to investigating on assignment, got %s", reloaded.Stage)
		}

		// 11. Timeline: an analyst note is recorded on the investigation timeline.
		if err := h.incSvc.AddNote(h.ctx, h.principal, inc.ID, "Confirmed malware on finance laptop; isolating."); err != nil {
			t.Fatalf("11. add timeline note: %v", err)
		}

		// 12. Playbook: run a containment playbook tied to THIS incident. Default
		//     authority is 'observe' → containment needs approval → then approve.
		pbs, err := h.soarSvc.ListPlaybooks(h.ctx, h.tenantID)
		if err != nil || len(pbs) == 0 {
			t.Fatalf("12. expected a seeded playbook: %v", err)
		}
		run, err := h.soarSvc.Run(h.ctx, h.principal, pbs[0].ID, &inc.ID)
		if err != nil {
			t.Fatalf("12. run playbook: %v", err)
		}
		if run.IncidentID == nil || *run.IncidentID != inc.ID {
			t.Fatalf("12. playbook run not tied to incident: %v", run.IncidentID)
		}
		if run.Status == soar.RunPendingApproval {
			if _, err := h.soarSvc.Approve(h.ctx, h.principal, run.ID); err != nil {
				t.Fatalf("12. approve containment: %v", err)
			}
		}

		// 13. Close incident: with a closure note (records a status timeline entry).
		if err := h.incSvc.Close(h.ctx, h.principal, inc.ID, "Contained and remediated."); err != nil {
			t.Fatalf("13. close incident: %v", err)
		}
		closed, _ := h.incSvc.Get(h.ctx, h.tenantID, inc.ID)
		if closed.Stage != incident.StageClosed || closed.ClosedAt == nil {
			t.Fatalf("13. incident not closed: stage=%s closedAt=%v", closed.Stage, closed.ClosedAt)
		}

		// 14. Timeline is the accumulated audit trail of the case: promote (seed) +
		//     assign + note + close = at least 4 ordered entries.
		tl, _ := h.incSvc.Timeline(h.ctx, h.tenantID, inc.ID)
		if len(tl) < 4 {
			t.Fatalf("14. expected >=4 timeline entries (promote/assign/note/close), got %d", len(tl))
		}
		var haveAssign, haveClose bool
		for _, e := range tl {
			if e.Kind == "status" && len(e.Note) >= 8 && e.Note[:8] == "Assigned" {
				haveAssign = true
			}
			if e.Kind == "status" && len(e.Note) >= 6 && e.Note[:6] == "Closed" {
				haveClose = true
			}
		}
		if !haveAssign || !haveClose {
			t.Fatalf("14. timeline missing assign/close markers (assign=%v close=%v)", haveAssign, haveClose)
		}

		// 15. Audit trail: the platform's immutable audit_log captured the login.
		//     (HTTP mutations are audited by middleware; here we assert the auth
		//     event that the service layer writes directly.)
		var audits int
		_ = h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT count(*) FROM audit_log WHERE action='auth.login' AND actor_email=$1`, h.email).Scan(&audits)
		})
		if audits < 1 {
			t.Fatal("15. audit trail missing the login event")
		}
	})

	t.Run("TicketingMirrorsIncidentOnOpen", func(t *testing.T) {
		// Promote a fresh alert; the incident open must mirror to the ITSM (stub) and
		// record the external ticket ref on the case timeline (outbound integration).
		ev := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: h.tenantID, Severity: "high", Source: "tkt"}
		a, ins, err := h.alertSvc.CreateFromEvent(h.ctx, ev, alert.Spec{Title: "tkt-alert", Severity: "high", DedupeKey: ev.ID.String() + ":tkt"})
		if err != nil || !ins {
			t.Fatalf("seed alert: ins=%v err=%v", ins, err)
		}
		inc, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, a.ID)
		if err != nil {
			t.Fatalf("promote: %v", err)
		}
		tl, _ := h.incSvc.Timeline(h.ctx, h.tenantID, inc.ID)
		var hasTicket bool
		for _, e := range tl {
			if e.Kind == "action" && strings.Contains(e.Note, "Ticket created: INC-TEST-1") {
				hasTicket = true
			}
		}
		if !hasTicket {
			t.Fatalf("incident timeline should record the mirrored ticket ref; entries=%d", len(tl))
		}
	})

	t.Run("ConnectorExpansion_CrowdStrikeThroughPipeline", func(t *testing.T) {
		// A NEW vendor (CrowdStrike) plugs into the SAME pipeline: webhook connector →
		// ingest → source normalizer → event store → detection → alert. No downstream
		// code is vendor-specific — this proves "integration-first, not -dependent".
		res, err := h.connSvc.Create(h.ctx, h.tenantID, connector.CreateInput{Kind: connector.KindWebhook, Name: "falcon"})
		if err != nil {
			t.Fatalf("create connector: %v", err)
		}
		nid := "cs-" + uuid.NewString()
		evts := []ingestion.IngestInput{{
			Source: "crowdstrike-falcon", NativeID: nid,
			Data: map[string]any{
				"detection_name": "WindowsMalware.CobaltStrike", // matches the 'malware' rule
				"severity":       float64(90),                   // 1-100 → critical
				"device":         map[string]any{"hostname": "EC2-WEB-3"},
				"user_name":      "svc-web",
				"technique_id":   "T1055",
			},
		}}
		if n, err := h.connSvc.IngestWebhook(h.ctx, res.Connector.ID, res.SourceKey, evts); err != nil || n != 1 {
			t.Fatalf("crowdstrike webhook ingest: n=%d err=%v", n, err)
		}
		if _, err := h.worker.RunOnce(h.ctx); err != nil {
			t.Fatalf("worker: %v", err)
		}
		alerts, _ := h.alertSvc.List(h.ctx, h.tenantID, "")
		var found *alert.Alert
		for i := range alerts {
			if alerts[i].Source == "crowdstrike-falcon" {
				found = &alerts[i]
				break
			}
		}
		if found == nil {
			t.Fatal("CrowdStrike detection did not flow through the shared pipeline to an alert")
		}
		// The alert's TargetRef proves the CrowdStrike normalizer ran inside the real
		// webhook→worker→detect path (alert severity itself is the RULE's severity, not
		// the event's — the 1-100→critical banding is covered by the unit test).
		if found.TargetRef != "host:EC2-WEB-3" {
			t.Errorf("normalizer did not map the Falcon device through the pipeline: target=%q", found.TargetRef)
		}
	})

	t.Run("ReportingSummaryAggregates", func(t *testing.T) {
		// Self-contained: raise a fresh high-severity alert and promote it, then the
		// tenant summary must reflect it (aggregates are tenant-scoped via RLS).
		ev := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: h.tenantID, Severity: "high", Source: "rep"}
		spec := alert.Spec{Title: "rep-alert", Severity: "high", DedupeKey: ev.ID.String() + ":rep"}
		a, ins, err := h.alertSvc.CreateFromEvent(h.ctx, ev, spec)
		if err != nil || !ins {
			t.Fatalf("seed alert: ins=%v err=%v", ins, err)
		}
		if _, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, a.ID); err != nil {
			t.Fatalf("seed incident: %v", err)
		}

		// Ingest a real event through the pipeline so it lands in the EventStore;
		// the summary's event count must come from the store (Postgres or ClickHouse).
		if _, err := h.ingest.Ingest(h.ctx, h.tenantID, ingestion.IngestInput{Source: "rep", NativeID: "rep-" + uuid.NewString(), Severity: "low"}); err != nil {
			t.Fatalf("seed event: %v", err)
		}
		if _, err := h.worker.RunOnce(h.ctx); err != nil {
			t.Fatalf("worker: %v", err)
		}

		sum, err := h.repSvc.Summary(h.ctx, h.tenantID)
		if err != nil {
			t.Fatalf("summary: %v", err)
		}
		if sum.GeneratedAt.IsZero() {
			t.Fatal("summary GeneratedAt must be set")
		}
		if sum.AlertsBySeverity["high"] < 1 {
			t.Fatalf("expected >=1 high-severity alert in summary, got %v", sum.AlertsBySeverity)
		}
		if sum.OpenIncidents < 1 || len(sum.IncidentsByStage) == 0 {
			t.Fatalf("expected >=1 open incident in summary: open=%d byStage=%v", sum.OpenIncidents, sum.IncidentsByStage)
		}
		// Event count comes from the EventStore (the point of this gate).
		if sum.EventsLast24h < 1 {
			t.Fatalf("expected EventsLast24h >=1 from the EventStore, got %d", sum.EventsLast24h)
		}
	})

	t.Run("BillingIngestQuota", func(t *testing.T) {
		// Self-contained: ingest two distinct raw events so today's meter is >= 2,
		// independent of other subtests' ordering.
		for _, nid := range []string{"bill-" + uuid.NewString(), "bill-" + uuid.NewString()} {
			if _, err := h.ingest.Ingest(h.ctx, h.tenantID, ingestion.IngestInput{Source: "bill", NativeID: nid, Severity: "low"}); err != nil {
				t.Fatalf("seed ingest: %v", err)
			}
		}
		// Default entitlement is generous → within quota.
		if ok, err := h.billSvc.WithinIngestQuota(h.ctx, h.tenantID, 0); err != nil || !ok {
			t.Fatalf("default quota should allow ingest: ok=%v err=%v", ok, err)
		}
		// Tighten the cap to 1 → the tenant is already over it → blocked.
		if _, err := h.billSvc.Set(h.ctx, h.tenantID, billing.Entitlements{Tier: "trial", EventsPerDay: 1}); err != nil {
			t.Fatalf("set entitlements: %v", err)
		}
		if ok, err := h.billSvc.WithinIngestQuota(h.ctx, h.tenantID, 0); err != nil || ok {
			t.Fatalf("with cap=1 and prior events, ingest must be blocked: ok=%v err=%v", ok, err)
		}
		// A non-positive cap is clamped to the platform default (not 0 = lockout).
		ent, err := h.billSvc.Set(h.ctx, h.tenantID, billing.Entitlements{Tier: "standard", EventsPerDay: 0})
		if err != nil {
			t.Fatalf("set (clamp): %v", err)
		}
		if ent.EventsPerDay != 100000 {
			t.Fatalf("non-positive EventsPerDay must clamp to 100000, got %d", ent.EventsPerDay)
		}
		if ok, _ := h.billSvc.WithinIngestQuota(h.ctx, h.tenantID, 0); !ok {
			t.Fatal("after restoring a generous cap, ingest should be allowed again")
		}
	})

	t.Run("MFAEnrollActivateEnforce", func(t *testing.T) {
		uri, secret, err := h.iamSvc.EnrollMFA(h.ctx, h.principal)
		if err != nil || secret == "" || len(uri) < 10 {
			t.Fatalf("enroll: uri=%q err=%v", uri, err)
		}
		// Before activation, login still works without a code.
		if _, err := h.iamSvc.Login(h.ctx, h.email, "password123", "", "r"); err != nil {
			t.Fatalf("login pre-activation should work: %v", err)
		}
		code, _ := totp.Code(secret, time.Now())
		if err := h.iamSvc.ActivateMFA(h.ctx, h.principal, code); err != nil {
			t.Fatalf("activate: %v", err)
		}
		// After activation, login WITHOUT a code must fail.
		if _, err := h.iamSvc.Login(h.ctx, h.email, "password123", "", "r"); err == nil {
			t.Fatal("SECURITY: login without MFA code must fail once MFA is enabled")
		}
		// Login WITH a valid code succeeds.
		code2, _ := totp.Code(secret, time.Now())
		if _, err := h.iamSvc.Login(h.ctx, h.email, "password123", code2, "r"); err != nil {
			t.Fatalf("login with MFA code should succeed: %v", err)
		}
		// Cleanup: disable MFA.
		code3, _ := totp.Code(secret, time.Now())
		if err := h.iamSvc.DisableMFA(h.ctx, h.principal, code3); err != nil {
			t.Fatalf("disable: %v", err)
		}
	})
}
