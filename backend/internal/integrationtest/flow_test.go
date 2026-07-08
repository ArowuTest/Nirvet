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

	"github.com/ArowuTest/nirvet/internal/ai"
	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/billing"
	"github.com/ArowuTest/nirvet/internal/connector"
	"github.com/ArowuTest/nirvet/internal/correlation"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/entitygraph"
	"github.com/ArowuTest/nirvet/internal/evidence"
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
	principal auth.Principal // analyst who requests SOAR runs
	approver  auth.Principal // distinct senior (soc_manager) who approves — four-eyes
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
	corrSvc  *correlation.Service
	events   eventstore.EventStore
	evidence *evidence.Service
	assetSvc *asset.Service
	graphSvc *entitygraph.Service
	aiSvc    *ai.Service
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
	// A distinct senior user (soc_manager) to approve SOAR runs — the requester may
	// not approve their own run (separation of duties), so approvals need a second
	// principal that is both a different user and a senior role.
	approverEmail := "approver-" + uuid.NewString() + "@t"
	au, err := iamSvc.Create(ctx, tn.ID, iam.CreateInput{Email: approverEmail, Password: "password123", Role: auth.RoleSOCManager})
	if err != nil {
		t.Fatalf("create approver: %v", err)
	}
	approver := auth.Principal{UserID: au.ID, TenantID: tn.ID, Role: auth.RoleSOCManager, Email: approverEmail}

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cipher, _ := crypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	blobs, _ := blobstore.NewLocal(t.TempDir())
	// Queue is interface-selected: with NIRVET_NATS_URL set the whole heartbeat runs
	// on NATS/JetStream (proving the ADR-0003 backend swap); else the Postgres queue.
	q, closeQ, _, qErr := queue.New(ctx, os.Getenv("NIRVET_NATS_URL"), db.Pool)
	if qErr != nil {
		t.Fatalf("queue: %v", qErr)
	}
	t.Cleanup(closeQ)
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
	incSvc := incident.NewService(incident.NewRepository(db), alertSvc, nil).WithAssignees(iamSvc).WithTicketer(stubTicketer{})
	// High-risk correlation clusters auto-open an incident (§6.7).
	corrSvc := correlation.NewService(correlation.NewRepository(db)).WithIncidenter(incSvc)
	assetSvc := asset.NewService(asset.NewRepository(db))
	incSvc.WithAssetContext(assetSvc) // critical-asset escalation (§6.8/§6.15)

	return &harness{
		ctx: ctx, db: db, tenantID: tn.ID, principal: principal, approver: approver, email: email,
		iamSvc:   iamSvc,
		ingest:   ingestSvc,
		worker:   ingestion.NewWorker(q, events, enr, detEng, alertSvc, log).WithCorrelator(corrSvc),
		alertSvc: alertSvc,
		incSvc:   incSvc,
		connSvc:  connector.NewService(connector.NewRepository(db), connector.NewVault(cipher), ingestSvc),
		soarSvc:  soar.NewService(soar.NewRepository(db)),
		billSvc:  billing.NewService(billing.NewRepository(db)),
		repSvc:   reporting.NewService(db, events),
		corrSvc:  corrSvc,
		events:   events,
		assetSvc: assetSvc,
		evidence: evidence.NewService(incSvc, alertSvc, events, assetSvc, db),
		graphSvc: entitygraph.NewService(alertSvc, incSvc, corrSvc, assetSvc),
		aiSvc:    ai.NewService(ai.NewGateway("", "test-model"), alertSvc, db).WithIncidentContext(incSvc, assetSvc),
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

	t.Run("LoginLockoutAfterRepeatedFailures", func(t *testing.T) {
		// Provision a throwaway user so the lockout doesn't affect the shared principal.
		email := "lock-" + uuid.NewString() + "@t"
		if _, err := h.iamSvc.Create(h.ctx, h.tenantID, iam.CreateInput{Email: email, Password: "password123", Role: auth.RoleAnalystT1}); err != nil {
			t.Fatalf("create user: %v", err)
		}
		// Five wrong-password attempts trip the lockout (maxFailedLogins).
		for i := 0; i < 5; i++ {
			if _, err := h.iamSvc.Login(h.ctx, email, "wrong", "", "req-lock"); err == nil {
				t.Fatalf("attempt %d with wrong password must fail", i+1)
			}
		}
		// Now even the CORRECT password is refused while the account is locked.
		if _, err := h.iamSvc.Login(h.ctx, email, "password123", "", "req-lock"); err == nil {
			t.Fatal("correct password must be refused while the account is locked out")
		}
		// Confirm the lock is recorded in the durable store.
		var locked bool
		_ = h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT locked_until IS NOT NULL AND locked_until > now() FROM users WHERE email=$1`, email).Scan(&locked)
		})
		if !locked {
			t.Fatal("expected locked_until to be set in the future after repeated failures")
		}
		// Simulate the cool-off elapsing: clearing the lock lets the correct password in.
		_ = h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE users SET locked_until=NULL, failed_login_attempts=0 WHERE email=$1`, email)
			return e
		})
		if _, err := h.iamSvc.Login(h.ctx, email, "password123", "", "req-lock"); err != nil {
			t.Fatalf("correct password must succeed once the lock has cleared: %v", err)
		}
	})

	t.Run("ChangePasswordRoundTrip", func(t *testing.T) {
		// A user can rotate their own password off the seed credential: the old one
		// stops working and the new one logs in. Wrong current password is rejected.
		if err := h.iamSvc.ChangePassword(h.ctx, h.principal, "wrong-current", "newpassword456"); err == nil {
			t.Fatal("change-password must reject an incorrect current password")
		}
		if err := h.iamSvc.ChangePassword(h.ctx, h.principal, "password123", "short"); err == nil {
			t.Fatal("change-password must reject a too-short new password")
		}
		if err := h.iamSvc.ChangePassword(h.ctx, h.principal, "password123", "newpassword456"); err != nil {
			t.Fatalf("change-password should succeed: %v", err)
		}
		if _, err := h.iamSvc.Login(h.ctx, h.email, "password123", "", "req-itest"); err == nil {
			t.Fatal("old password must no longer log in after a change")
		}
		if _, err := h.iamSvc.Login(h.ctx, h.email, "newpassword456", "", "req-itest"); err != nil {
			t.Fatalf("new password must log in after a change: %v", err)
		}
		// Restore the seed password so later subtests that rely on it still pass.
		if err := h.iamSvc.ChangePassword(h.ctx, h.principal, "newpassword456", "password123"); err != nil {
			t.Fatalf("restore password: %v", err)
		}
	})

	t.Run("AuditLogIsAppendOnly", func(t *testing.T) {
		// The audit trail is the evidentiary spine — the app role must not be able to
		// rewrite or erase it (SEC/NFR-003, migration 0017).
		err := h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE audit_log SET action='tamper'`)
			return e
		})
		if err == nil {
			t.Fatal("app role must NOT be able to UPDATE audit_log")
		}
		err = h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `DELETE FROM audit_log`)
			return e
		})
		if err == nil {
			t.Fatal("app role must NOT be able to DELETE from audit_log")
		}
	})

	t.Run("IngestReconcilesOrphanedRawEvent", func(t *testing.T) {
		// SEC Critical #4: a crash between StoreRaw and Enqueue leaves the raw event +
		// its blob durably persisted but with no normalize job (enqueued_at NULL). The
		// reconciler must re-enqueue it from the blob so the event is never lost.
		in := ingestion.IngestInput{Source: "recon", NativeID: "orphan-1", ClassName: "Malware recon-orphan", Severity: "high", TargetRef: "host:recon-1"}
		if _, err := h.ingest.Ingest(h.ctx, h.tenantID, in); err != nil {
			t.Fatalf("ingest: %v", err)
		}
		// Orphan it: drop the queued normalize job and clear the durability marker.
		if _, err := h.db.Pool.Exec(h.ctx,
			`DELETE FROM ingest_jobs WHERE state='queued' AND convert_from(payload,'UTF8') LIKE '%orphan-1%'`); err != nil {
			t.Fatalf("delete job: %v", err)
		}
		if err := h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE raw_events SET enqueued_at=NULL WHERE dedupe_key=$1`, "recon:orphan-1")
			return e
		}); err != nil {
			t.Fatalf("clear marker: %v", err)
		}
		// With no job, draining the worker must NOT produce the event.
		if _, err := h.worker.RunOnce(h.ctx); err != nil {
			t.Fatalf("drain(pre): %v", err)
		}
		if pre, _ := h.events.Query(h.ctx, h.tenantID, eventstore.Query{Search: "recon-orphan", Limit: 10}); len(pre) != 0 {
			t.Fatalf("event must not exist before reconciliation, got %d", len(pre))
		}
		// Reconcile (grace 0 = every unenqueued row) re-enqueues from the blob store.
		n, err := h.ingest.Reconcile(h.ctx, 0, 100)
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if n < 1 {
			t.Fatalf("reconcile should re-enqueue at least one orphan, got %d", n)
		}
		// Drain again: the recovered event is now normalized and stored.
		if _, err := h.worker.RunOnce(h.ctx); err != nil {
			t.Fatalf("drain(post): %v", err)
		}
		post, _ := h.events.Query(h.ctx, h.tenantID, eventstore.Query{Search: "recon-orphan", Limit: 10})
		if len(post) == 0 {
			t.Fatal("event must be recovered and stored after reconciliation")
		}
		if post[0].Severity != "high" {
			t.Fatalf("recovered event severity = %q, want high", post[0].Severity)
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

	t.Run("IncidentAtRiskQueue", func(t *testing.T) {
		// §6.8 at-risk queue: an open incident past its resolve deadline shows up as
		// at-risk with the breach flag set.
		ev := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: h.tenantID, Severity: "high", Source: "risk"}
		a, ins, err := h.alertSvc.CreateFromEvent(h.ctx, ev, alert.Spec{Title: "risk-alert", Severity: "high", DedupeKey: ev.ID.String() + ":risk"})
		if err != nil || !ins {
			t.Fatalf("seed alert: %v", err)
		}
		inc, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, a.ID)
		if err != nil {
			t.Fatalf("promote: %v", err)
		}
		if err := h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE incidents SET resolve_due_at = now() - interval '1 hour' WHERE id=$1`, inc.ID)
			return e
		}); err != nil {
			t.Fatalf("backdate: %v", err)
		}
		atRisk, err := h.incSvc.AtRisk(h.ctx, h.tenantID)
		if err != nil {
			t.Fatalf("at-risk: %v", err)
		}
		found := false
		for _, i := range atRisk {
			if i.ID == inc.ID {
				found = true
				if !i.ResolveBreached {
					t.Fatal("at-risk incident past resolve due must be flagged breached")
				}
			}
		}
		if !found {
			t.Fatal("a past-due open incident must appear in the at-risk queue")
		}
	})

	t.Run("AICopilotIncidentTriage", func(t *testing.T) {
		// §6.12: assistive-only triage grounded in the incident's own evidence, with the
		// offline deterministic fallback (no LLM key). Guardrails: assistive flag,
		// observed-only confidence, actions routed via approval, evidence-linked, audited.
		if _, err := h.assetSvc.Create(h.ctx, h.tenantID, asset.CreateInput{Ref: "host:triage", Name: "Triage Host", Kind: "host", Criticality: "critical"}); err != nil {
			t.Fatalf("asset: %v", err)
		}
		ev := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: h.tenantID, Severity: "high", Source: "ai", TargetRef: "host:triage"}
		a, ins, err := h.alertSvc.CreateFromEvent(h.ctx, ev, alert.Spec{Title: "ai-alert", Severity: "high", MITRE: []string{"T1059"}, DedupeKey: ev.ID.String() + ":ai"})
		if err != nil || !ins {
			t.Fatalf("seed alert: %v", err)
		}
		inc, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, a.ID)
		if err != nil {
			t.Fatalf("promote: %v", err)
		}
		sum, err := h.aiSvc.TriageIncident(h.ctx, h.principal, inc.ID)
		if err != nil {
			t.Fatalf("triage: %v", err)
		}
		if !sum.Assistive {
			t.Fatal("triage must be flagged assistive")
		}
		if sum.Confidence != "observed" {
			t.Fatalf("offline triage confidence should be observed, got %q", sum.Confidence)
		}
		if !strings.Contains(sum.Text, "approval workflow") {
			t.Fatal("assistive triage must route actions through the approval workflow (no self-execution)")
		}
		hasInc, hasAsset := false, false
		for _, e := range sum.Evidence {
			if e == "incident:"+inc.ID.String() {
				hasInc = true
			}
			if e == "asset:host:triage" {
				hasAsset = true
			}
		}
		if !hasInc || !hasAsset {
			t.Fatalf("evidence must reference the incident + affected asset, got %v", sum.Evidence)
		}
		var n int
		_ = h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='ai.triage_incident' AND target=$1`, "incident:"+inc.ID.String()).Scan(&n)
		})
		if n < 1 {
			t.Fatal("AI triage must be audited")
		}
	})

	t.Run("EntityGraphBlastRadius", func(t *testing.T) {
		// §6.9: the entity graph gathers everything touching a ref — alerts, the
		// incidents they belong to, and the matched asset.
		ref := "host:graph-target"
		if _, err := h.assetSvc.Create(h.ctx, h.tenantID, asset.CreateInput{Ref: ref, Name: "Graph Target", Kind: "host", Criticality: "medium"}); err != nil {
			t.Fatalf("register asset: %v", err)
		}
		ev := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: h.tenantID, Severity: "high", Source: "graph", TargetRef: ref}
		a, ins, err := h.alertSvc.CreateFromEvent(h.ctx, ev, alert.Spec{Title: "graph-alert", Severity: "high", DedupeKey: ev.ID.String() + ":graph"})
		if err != nil || !ins {
			t.Fatalf("seed alert: %v", err)
		}
		if _, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, a.ID); err != nil {
			t.Fatalf("promote: %v", err)
		}
		g, err := h.graphSvc.Build(h.ctx, h.tenantID, ref)
		if err != nil {
			t.Fatalf("build graph: %v", err)
		}
		if g.Summary.AlertCount < 1 || g.Summary.IncidentCount < 1 {
			t.Fatalf("graph must include the alert + incident, got alerts=%d incidents=%d", g.Summary.AlertCount, g.Summary.IncidentCount)
		}
		if g.Asset == nil || g.Asset.Ref != ref {
			t.Fatal("graph must match the inventory asset for the ref")
		}
		if g.Summary.MaxSeverity != "high" {
			t.Fatalf("graph max severity should be high, got %q", g.Summary.MaxSeverity)
		}
		if g.Summary.OpenIncidents < 1 {
			t.Fatalf("graph should count the open incident, got %d", g.Summary.OpenIncidents)
		}
		// An empty ref is rejected.
		if _, err := h.graphSvc.Build(h.ctx, h.tenantID, ""); err == nil {
			t.Fatal("empty ref must be rejected")
		}
	})

	t.Run("IncidentEscalatesForCriticalAsset", func(t *testing.T) {
		// §6.8/§6.15: a high-severity alert on a CRITICAL asset promotes to a CRITICAL
		// incident (severity raised, never lowered), with the escalation on the timeline.
		if _, err := h.assetSvc.Create(h.ctx, h.tenantID, asset.CreateInput{Ref: "host:crown-jewel", Name: "Crown Jewel DB", Kind: "host", Criticality: "critical"}); err != nil {
			t.Fatalf("register critical asset: %v", err)
		}
		ev := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: h.tenantID, Severity: "high", Source: "esc", TargetRef: "host:crown-jewel"}
		a, ins, err := h.alertSvc.CreateFromEvent(h.ctx, ev, alert.Spec{Title: "esc-alert", Severity: "high", DedupeKey: ev.ID.String() + ":esc"})
		if err != nil || !ins {
			t.Fatalf("seed alert: %v", err)
		}
		inc, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, a.ID)
		if err != nil {
			t.Fatalf("promote: %v", err)
		}
		if inc.Severity != "critical" {
			t.Fatalf("incident severity should escalate high→critical for a critical asset, got %q", inc.Severity)
		}
		tl, _ := h.incSvc.Timeline(h.ctx, h.tenantID, inc.ID)
		escalated := false
		for _, e := range tl {
			if strings.Contains(e.Note, "Severity escalated") {
				escalated = true
			}
		}
		if !escalated {
			t.Fatal("escalation must be recorded on the incident timeline")
		}
		// A medium-severity alert on the same critical asset also escalates to critical.
		ev2 := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: h.tenantID, Severity: "medium", Source: "esc", TargetRef: "host:crown-jewel"}
		a2, _, _ := h.alertSvc.CreateFromEvent(h.ctx, ev2, alert.Spec{Title: "esc2", Severity: "medium", DedupeKey: ev2.ID.String() + ":esc2"})
		inc2, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, a2.ID)
		if err != nil {
			t.Fatalf("promote2: %v", err)
		}
		if inc2.Severity != "critical" {
			t.Fatalf("medium alert on critical asset should escalate to critical, got %q", inc2.Severity)
		}
		// Control: an alert on an UNknown asset keeps its own severity (no escalation).
		ev3 := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: h.tenantID, Severity: "low", Source: "esc", TargetRef: "host:unmanaged"}
		a3, _, _ := h.alertSvc.CreateFromEvent(h.ctx, ev3, alert.Spec{Title: "esc3", Severity: "low", DedupeKey: ev3.ID.String() + ":esc3"})
		inc3, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, a3.ID)
		if err != nil {
			t.Fatalf("promote3: %v", err)
		}
		if inc3.Severity != "low" {
			t.Fatalf("alert on unmanaged asset must NOT escalate, got %q", inc3.Severity)
		}
	})

	t.Run("EvidencePackAssembly", func(t *testing.T) {
		// SRS §6.13: an evidence pack bundles the case + its alerts + the underlying
		// events + the audit trail, with a tamper-evident checksum manifest.
		ev := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: h.tenantID, Severity: "high", Source: "evi", ClassName: "Evidence probe", ActorRef: "user:e", TargetRef: "host:e"}
		if _, err := h.events.Append(h.ctx, h.tenantID, []eventstore.NormalizedEvent{ev}); err != nil {
			t.Fatalf("append event: %v", err)
		}
		a, ins, err := h.alertSvc.CreateFromEvent(h.ctx, ev, alert.Spec{Title: "evi-alert", Severity: "high", DedupeKey: ev.ID.String() + ":evi"})
		if err != nil || !ins {
			t.Fatalf("seed alert: %v ins=%v", err, ins)
		}
		// Register the affected asset so the pack carries asset context (§6.15).
		if _, err := h.assetSvc.Create(h.ctx, h.tenantID, asset.CreateInput{Ref: "host:e", Name: "Evidence Host", Kind: "host", Criticality: "high"}); err != nil {
			t.Fatalf("register asset: %v", err)
		}
		inc, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, a.ID)
		if err != nil {
			t.Fatalf("promote: %v", err)
		}
		// Simulate the mutation-audit row the HTTP middleware would write on a close
		// (its Action carries the incident id in the URL path).
		if err := h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO audit_log (actor_email, action, metadata, request_id) VALUES ($1,$2,'{}',$3)`,
				h.email, "POST /incidents/"+inc.ID.String()+"/close", "req-evi")
			return e
		}); err != nil {
			t.Fatalf("seed audit: %v", err)
		}

		pack, err := h.evidence.Build(h.ctx, h.principal, inc.ID, time.Now())
		if err != nil {
			t.Fatalf("build pack: %v", err)
		}
		if pack.Incident == nil || pack.Incident.ID != inc.ID {
			t.Fatal("pack must contain the incident")
		}
		if len(pack.Alerts) == 0 || pack.Alerts[0].ID != a.ID {
			t.Fatal("pack must contain the promoted alert")
		}
		foundEvent := false
		for _, e := range pack.Events {
			if e.ID == ev.ID {
				foundEvent = true
			}
		}
		if !foundEvent {
			t.Fatal("pack must contain the underlying event")
		}
		foundAudit := false
		for _, ae := range pack.Audit {
			if strings.Contains(ae.Action, inc.ID.String()) {
				foundAudit = true
			}
		}
		if !foundAudit {
			t.Fatal("pack must contain the incident's audit entry")
		}
		if pack.Manifest.PackChecksum == "" || pack.Manifest.SectionChecksum["events"] == "" {
			t.Fatal("pack manifest checksums must be set")
		}
		if pack.Manifest.Counts["alerts"] != len(pack.Alerts) {
			t.Fatalf("manifest alert count %d must match %d", pack.Manifest.Counts["alerts"], len(pack.Alerts))
		}
		// Affected-asset context (§6.15): the registered host must appear in the pack.
		foundAsset := false
		for _, as := range pack.Assets {
			if as.Ref == "host:e" && as.Criticality == "high" {
				foundAsset = true
			}
		}
		if !foundAsset {
			t.Fatal("pack must contain the affected asset (host:e, high criticality)")
		}
	})

	t.Run("AssetRegistryUpsert", func(t *testing.T) {
		// Registering the same ref twice updates in place (idempotent), and FindByRefs
		// resolves it. Tenant-scoped.
		in := asset.CreateInput{Ref: "user:jane@acme.com", Name: "Jane", Kind: "user", Criticality: "medium"}
		a1, err := h.assetSvc.Create(h.ctx, h.tenantID, in)
		if err != nil {
			t.Fatalf("create asset: %v", err)
		}
		in.Criticality = "critical"
		in.Name = "Jane Doe (VIP)"
		a2, err := h.assetSvc.Create(h.ctx, h.tenantID, in)
		if err != nil {
			t.Fatalf("upsert asset: %v", err)
		}
		if a2.ID != a1.ID {
			t.Fatal("re-registering the same ref must update in place, not create a new asset")
		}
		got, _ := h.assetSvc.Get(h.ctx, h.tenantID, a1.ID)
		if got.Criticality != "critical" || got.Name != "Jane Doe (VIP)" {
			t.Fatalf("upsert must update attributes, got crit=%s name=%q", got.Criticality, got.Name)
		}
		found, _ := h.assetSvc.FindByRefs(h.ctx, h.tenantID, []string{"user:jane@acme.com", "host:nonexistent"})
		if len(found) != 1 || found[0].Ref != "user:jane@acme.com" {
			t.Fatalf("FindByRefs should resolve exactly the known ref, got %d", len(found))
		}
		// Invalid criticality is rejected.
		if _, err := h.assetSvc.Create(h.ctx, h.tenantID, asset.CreateInput{Ref: "host:x", Name: "x", Criticality: "bogus"}); err == nil {
			t.Fatal("invalid criticality must be rejected")
		}
	})

	t.Run("IncidentSLATimersAndBreach", func(t *testing.T) {
		// Promote a fresh critical alert and verify SLA timers are stamped, the case is
		// acknowledged (analyst-owned) and not yet breached — then force the deadlines
		// into the past and confirm the derived breach flags flip.
		ev := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: h.tenantID, Severity: "critical", Source: "sla"}
		a, ins, err := h.alertSvc.CreateFromEvent(h.ctx, ev, alert.Spec{Title: "sla-alert", Severity: "critical", DedupeKey: ev.ID.String() + ":sla"})
		if err != nil || !ins {
			t.Fatalf("seed alert: %v ins=%v", err, ins)
		}
		inc, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, a.ID)
		if err != nil {
			t.Fatalf("promote: %v", err)
		}
		got, err := h.incSvc.Get(h.ctx, h.tenantID, inc.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.AckDueAt == nil || got.ResolveDueAt == nil {
			t.Fatal("SLA due-times must be stamped at creation")
		}
		if got.AcknowledgedAt == nil {
			t.Fatal("an analyst-promoted incident must be acknowledged")
		}
		if got.AckBreached || got.ResolveBreached {
			t.Fatalf("a just-created incident must not be breached (ack=%v resolve=%v)", got.AckBreached, got.ResolveBreached)
		}
		// Critical ack target is 15m: a fresh incident's ack deadline must be in the future.
		if !got.AckDueAt.After(got.CreatedAt) {
			t.Fatal("ack_due_at must be after created_at")
		}
		// Force the deadlines into the past → both SLAs should now read as breached.
		if err := h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE incidents SET ack_due_at = now() - interval '1 hour', resolve_due_at = now() - interval '1 hour', acknowledged_at = NULL WHERE id=$1`, inc.ID)
			return e
		}); err != nil {
			t.Fatalf("backdate SLA: %v", err)
		}
		breached, _ := h.incSvc.Get(h.ctx, h.tenantID, inc.ID)
		if !breached.AckBreached || !breached.ResolveBreached {
			t.Fatalf("past-due open incident must be breached (ack=%v resolve=%v)", breached.AckBreached, breached.ResolveBreached)
		}
	})

	t.Run("SLABreachSweepAlertsOnce", func(t *testing.T) {
		// §6.8 follow-on: the sweeper alerts on a breached deadline exactly once
		// (idempotent via the notified marker) and records it on the timeline.
		ev := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: h.tenantID, Severity: "high", Source: "slabr"}
		a, ins, err := h.alertSvc.CreateFromEvent(h.ctx, ev, alert.Spec{Title: "slabr-alert", Severity: "high", DedupeKey: ev.ID.String() + ":slabr"})
		if err != nil || !ins {
			t.Fatalf("seed alert: %v", err)
		}
		inc, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, a.ID)
		if err != nil {
			t.Fatalf("promote: %v", err)
		}
		// Back-date both deadlines and clear acknowledgement so ack AND resolve breach.
		if err := h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE incidents SET acknowledged_at=NULL, ack_due_at=now()-interval '2 hours', resolve_due_at=now()-interval '1 hour' WHERE id=$1`, inc.ID)
			return e
		}); err != nil {
			t.Fatalf("backdate: %v", err)
		}
		countNotes := func() (ack, res int) {
			tl, _ := h.incSvc.Timeline(h.ctx, h.tenantID, inc.ID)
			for _, e := range tl {
				if strings.Contains(e.Note, "SLA ack deadline breached") {
					ack++
				}
				if strings.Contains(e.Note, "SLA resolve deadline breached") {
					res++
				}
			}
			return
		}
		if _, err := h.incSvc.SweepSLABreaches(h.ctx, time.Now(), 500); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		if ack, res := countNotes(); ack != 1 || res != 1 {
			t.Fatalf("expected one ack + one resolve breach note, got ack=%d resolve=%d", ack, res)
		}
		// Idempotent: a second sweep must not re-alert (markers were set).
		if _, err := h.incSvc.SweepSLABreaches(h.ctx, time.Now(), 500); err != nil {
			t.Fatalf("sweep2: %v", err)
		}
		if ack, res := countNotes(); ack != 1 || res != 1 {
			t.Fatalf("SLA breach must alert exactly once, got ack=%d resolve=%d after re-sweep", ack, res)
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
		// Separation of duties: the analyst who requested the run cannot approve it.
		if _, err := h.soarSvc.Approve(h.ctx, h.principal, run.ID); err == nil {
			t.Fatal("four-eyes: the requester must NOT be able to approve their own run")
		}
		// A distinct senior approver completes it.
		approved, err := h.soarSvc.Approve(h.ctx, h.approver, run.ID)
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
		//     authority is 'observe' → containment needs approval → a senior approver
		//     (not the requesting analyst — four-eyes) approves.
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
			if _, err := h.soarSvc.Approve(h.ctx, h.approver, run.ID); err != nil {
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

	t.Run("AlertCorrelationClustersByEntity", func(t *testing.T) {
		// Two malware alerts on the SAME host must cluster into ONE risk-scored
		// correlation (alert-fatigue reduction, §6.7) — proven through the real
		// ingest → detect → alert → correlate worker path.
		host := "host:CORR-" + uuid.NewString()
		for _, nid := range []string{"c1-" + uuid.NewString(), "c2-" + uuid.NewString()} {
			if _, err := h.ingest.Ingest(h.ctx, h.tenantID, ingestion.IngestInput{
				Source: "corr-test", NativeID: nid, ClassName: "WinMalware.Gen", Severity: "critical", TargetRef: host,
			}); err != nil {
				t.Fatalf("ingest: %v", err)
			}
		}
		if _, err := h.worker.RunOnce(h.ctx); err != nil {
			t.Fatalf("worker: %v", err)
		}
		clusters, _ := h.corrSvc.List(h.ctx, h.tenantID, "open")
		var found *correlation.Correlation
		for i := range clusters {
			if clusters[i].Entity == host {
				found = &clusters[i]
				break
			}
		}
		if found == nil {
			t.Fatal("expected a correlation cluster for the shared host")
		}
		if found.AlertCount != 2 {
			t.Fatalf("both alerts on the host should cluster: alert_count=%d", found.AlertCount)
		}
		if found.RiskScore <= 0 {
			t.Fatalf("cluster should be risk-scored, got %d", found.RiskScore)
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
		// webhook→worker→detect path (alert severity itself is the RULE's severity).
		if found.TargetRef != "host:EC2-WEB-3" {
			t.Errorf("normalizer did not map the Falcon device through the pipeline: target=%q", found.TargetRef)
		}
		// REGRESSION GUARD (severity-at-the-door bug): the ingest door must NOT default
		// severity before the mapper runs, or the CrowdStrike 1-100 score→band
		// derivation is dead code. The stored event's severity must be the derived
		// "critical" (score 90), not "informational".
		evs, qerr := h.events.Query(h.ctx, h.tenantID, eventstore.Query{Search: "CobaltStrike", Limit: 20})
		if qerr != nil {
			t.Fatalf("query events: %v", qerr)
		}
		var csEvent *eventstore.NormalizedEvent
		for i := range evs {
			if evs[i].Source == "crowdstrike-falcon" {
				csEvent = &evs[i]
				break
			}
		}
		if csEvent == nil {
			t.Fatal("CrowdStrike event not found in the event store")
		}
		if csEvent.Severity != "critical" {
			t.Fatalf("CrowdStrike score 90 must derive to severity=critical through the ingest door, got %q "+
				"(severity-at-the-door regression)", csEvent.Severity)
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
		// SLA posture (§6.8) is populated; the just-promoted incident is open + on-track.
		if sum.SLA.OpenIncidents < 1 {
			t.Fatalf("SLA posture must count the open incident, got %d", sum.SLA.OpenIncidents)
		}

		// Now force a resolve-deadline breach and confirm the posture reflects it.
		ev2 := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: h.tenantID, Severity: "high", Source: "repsla"}
		a2, ins2, err := h.alertSvc.CreateFromEvent(h.ctx, ev2, alert.Spec{Title: "repsla-alert", Severity: "high", DedupeKey: ev2.ID.String() + ":repsla"})
		if err != nil || !ins2 {
			t.Fatalf("seed sla alert: %v", err)
		}
		inc2, err := h.incSvc.CreateFromAlert(h.ctx, h.principal, a2.ID)
		if err != nil {
			t.Fatalf("promote sla incident: %v", err)
		}
		if err := h.db.WithTenant(h.ctx, h.tenantID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE incidents SET resolve_due_at = now() - interval '1 hour' WHERE id=$1`, inc2.ID)
			return e
		}); err != nil {
			t.Fatalf("backdate resolve due: %v", err)
		}
		sum2, err := h.repSvc.Summary(h.ctx, h.tenantID)
		if err != nil {
			t.Fatalf("summary2: %v", err)
		}
		if sum2.SLA.ResolveBreaching < 1 {
			t.Fatalf("SLA posture must count the resolve-breaching incident, got %d", sum2.SLA.ResolveBreaching)
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
