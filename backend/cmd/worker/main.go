// Command worker runs the ingestion/normalization worker as a standalone process
// (production). In development the api process can run it inline instead.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/connector"
	"github.com/ArowuTest/nirvet/internal/correlation"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/notify"
	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/config"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/logger"
	"github.com/ArowuTest/nirvet/internal/platform/queue"
	"github.com/ArowuTest/nirvet/internal/platform/tracing"
	"github.com/ArowuTest/nirvet/internal/platformadmin"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/soarwire"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/ArowuTest/nirvet/internal/threatintel"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	log := logger.New(cfg.Env)
	log.Info("nirvet worker starting", "env", cfg.Env)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	traceShutdown, err := tracing.Init(ctx, tracing.Config{
		ServiceName: "nirvet-worker", ServiceVer: cfg.ServiceVer,
		Environment: cfg.Env, OTLPEndpoint: cfg.OTLPEndpoint,
	})
	if err != nil {
		log.Error("tracing init failed", "err", err)
		os.Exit(1)
	}
	defer func() { _ = traceShutdown(context.Background()) }()

	db, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("database connect failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	events, closeEvents, esBackend, err := eventstore.New(ctx, cfg.ClickHouseDSN, db)
	if err != nil {
		log.Error("event store init failed", "err", err)
		os.Exit(1)
	}
	defer func() { _ = closeEvents() }()
	log.Info("event store ready", "backend", esBackend)
	jobs, closeJobs, queueBackend, err := queue.New(ctx, cfg.NATSURL, db.Pool)
	if err != nil {
		log.Error("queue init failed", "err", err)
		os.Exit(1)
	}
	defer closeJobs()
	log.Info("queue backend ready", "backend", queueBackend)
	alertSvc := alert.NewService(alert.NewRepository(db))
	detEngine := detection.NewEngine(detection.NewRepository(db))
	enricher := threatintel.NewEnricher(threatintel.NewRepository(db))
	// The worker (not the api) owns the SLA sweeper in production, so it must wire the
	// SAME durable-notification path the api does: an outbox-backed notify service, the
	// enqueuer that writes breach notifications transactionally, and the tenant service
	// that resolves the per-severity escalation matrix (§6.1/§6.8). Without WithEnqueuer
	// the sweeper claims breaches but enqueues nothing — the prod bug this fixes.
	outboxRepo := notify.NewOutboxRepository(db)
	notifySvc := notify.NewService(log).WithOutbox(outboxRepo)
	tenantSvc := tenant.NewService(tenant.NewRepository(db))
	incidentSvc := incident.NewService(incident.NewRepository(db), alertSvc, notifySvc).
		WithEnqueuer(outboxRepo).WithEscalation(tenantSvc).WithSLA(tenantSvc).
		// §6.18 #122 M-2: the SLA sweeper consults the maintenance gate — a non-critical breach is deferred while
		// the tenant is inside a pause-SLA window; a critical (P1) always breaks through. Dormant until an admin
		// opens a window.
		WithMaintenance(platformadmin.NewMaintenanceService(platformadmin.NewRepository(db)))
	correlationSvc := correlation.NewService(correlation.NewRepository(db)).WithIncidenter(incidentSvc).WithPolicy(tenantSvc)
	wk := ingestion.NewWorker(jobs, events, enricher, detEngine, alertSvc, log).WithCorrelator(correlationSvc).WithNormQuality(ingestion.NewNormQuality(db))

	// Connector poller: pulls Microsoft Graph/Defender alerts through ingestion.
	cipher, err := crypto.New(cfg.KMSKeyName, cfg.SecretMasterKey, log)
	if err != nil {
		log.Error("crypto init failed", "err", err)
		os.Exit(1)
	}
	blobs, err := blobstore.New(cfg.GCSBucket, cfg.BlobDir)
	if err != nil {
		log.Error("blobstore init failed", "err", err)
		os.Exit(1)
	}
	ingestSvc := ingestion.NewService(ingestion.NewRepository(db), jobs, nil, blobs)
	poller := connector.NewPoller(connector.NewRepository(db), connector.NewVault(cipher), ingestSvc, log)
	go poller.Start(ctx, time.Minute)
	// §6.4 #118 host-telemetry health (US-032): a host source (osquery/Wazuh) that reported before but has gone
	// silent is a detection GAP — alert once per silence episode. last-seen is recorded on every keyed ingest;
	// this is the silence half. (interval 5m; silent after 30m of no events; ≤200/tick.)
	go connector.NewSilenceSweeper(connector.NewRepository(db), alertSvc).Start(ctx, log, 5*time.Minute, 30*time.Minute, 200)
	// §6.18 #122 Reinf-B: auto-revert protected feature flags whose time-box has expired to their secure default —
	// a temporary loosening (e.g. destructive-SOAR gate opened for an incident) can never persist indefinitely.
	go platformadmin.NewService(platformadmin.NewRepository(db), alertSvc).StartRevertSweep(ctx, log, time.Minute)
	// Ingestion durability: re-enqueue any raw event orphaned by a crash between
	// StoreRaw and Enqueue (SEC Critical #4). The worker process owns this sweep.
	go ingestSvc.StartReconciler(ctx, log, 30*time.Second, 60*time.Second, 100)
	// Requeue jobs stranded in 'running' by a hard worker crash (R6-C2); NATS self-heals (no-op).
	go queue.StartReaper(ctx, jobs, log, time.Minute, 5*time.Minute)
	// SLA breach alerting (§6.8): notify + timeline once per breached deadline.
	go incidentSvc.StartSLASweeper(ctx, log, time.Minute, 200)
	// Deliver the durable notifications the sweeper enqueues (§6.16). The worker owns
	// the dispatcher in production; the api runs it only in inline-worker (dev) mode.
	go notifySvc.StartDispatcher(ctx, log, 15*time.Second, 200)

	// §6.11 slice B crash-recovery: re-drive SOAR runs stranded with a connector step 'executing'
	// past the visibility window (Phase B/C interrupted by a hard crash). The supervisor resumes at
	// Phase B (never re-runs the claim), so the rate budget + intent audit happen exactly once. The
	// worker owns this loop; the Actioner registry is empty until real vendor actions register, so
	// this is dormant (no stranded connector steps exist) until destructive execution is enabled.
	soarRepo := soar.NewRepository(db)
	soarExecs := soar.NewExecutors().
		Register("notify_analyst", soar.NewNotifyExecutor(outboxRepo)).
		Register("notify_customer", soar.NewNotifyExecutor(outboxRepo))
	// CredDecryptor (slice C): vault-decrypts a tenant's connector creds for Phase B of a resumed
	// containment run. §6.11 slice C registers the real Defender isolate/release Actioners so the resume
	// loop can re-drive a stranded containment step (dormant until a tenant enables destructive actions).
	soarCreds := connector.NewCredentialResolver(connector.NewRepository(db), connector.NewVault(cipher))
	soarReg := soar.NewActionerRegistry()
	for _, a := range connector.NewDefenderActioner("", "", "", nil).Actioners() {
		soarReg.Register(a)
	}
	for _, a := range connector.NewEntraActioner("", "", "", nil).Actioners() { // §6.11 vendor-2: identity containment
		soarReg.Register(a)
	}
	// §6.11 reconciler (D-3) + D5 guard: surface a failed/stalled/withheld containment (BOTH an internal triage
	// alert and a durable HIGH notification), refuse a protected-identity target (blast-radius), then run the
	// confirmation loop in the worker.
	soarSup := soar.NewSupervisor(soarRepo, soarReg, soarCreds, log).
		WithAlerter(soarwire.NewContainmentAlerter(alertSvc, outboxRepo)).
		WithGuard(connector.NewEntraProtectedGuard(soarRepo, "", "", "", nil))
	soarSvc := soar.NewService(soarRepo).WithAuthorizer(tenantSvc).WithExecutors(soarExecs).WithSupervisor(soarSup)
	go soarSvc.StartResumeLoop(ctx, log, time.Minute, 300)
	// §6.11 reconciler: confirm submitted containments took effect; surface failures/stalls (read-only poll).
	go soarSup.StartReconcileLoop(ctx, log, time.Minute)

	log.Info("nirvet worker running (ingest + connector poller + reconciler + sla sweeper + notify dispatcher + soar resume + soar reconcile)")
	wk.Start(ctx, time.Second)
	log.Info("nirvet worker stopped")
}
