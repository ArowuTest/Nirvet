// Command api is the Nirvet platform HTTP API. It wires the platform foundation
// (config, db+RLS, auth, crypto, eventstore, queue) to the domain modules and
// serves the SOC value loop: tenant -> user/login -> ingest -> alert -> incident.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ArowuTest/nirvet/api"
	"github.com/ArowuTest/nirvet/internal/ai"
	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/billing"
	"github.com/ArowuTest/nirvet/internal/compliance"
	"github.com/ArowuTest/nirvet/internal/connector"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/iam"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/notify"
	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/config"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/logger"
	"github.com/ArowuTest/nirvet/internal/platform/metrics"
	"github.com/ArowuTest/nirvet/internal/platform/queue"
	"github.com/ArowuTest/nirvet/internal/platform/ratelimit"
	"github.com/ArowuTest/nirvet/internal/platform/tracing"
	"github.com/ArowuTest/nirvet/internal/reporting"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/sso"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/ArowuTest/nirvet/internal/threatintel"
	"github.com/ArowuTest/nirvet/internal/ticketing"
	"github.com/redis/go-redis/v9"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	log := logger.New(cfg.Env)
	log.Info("nirvet api starting", "env", cfg.Env, "addr", cfg.HTTPAddr)

	ctx := context.Background()

	// Distributed tracing (NFR-007). No-op unless NIRVET_OTLP_ENDPOINT is set.
	traceShutdown, err := tracing.Init(ctx, tracing.Config{
		ServiceName: "nirvet-api", ServiceVer: cfg.ServiceVer,
		Environment: cfg.Env, OTLPEndpoint: cfg.OTLPEndpoint,
	})
	if err != nil {
		log.Error("tracing init failed", "err", err)
		os.Exit(1)
	}
	defer func() { _ = traceShutdown(context.Background()) }()
	if cfg.OTLPEndpoint != "" {
		log.Info("tracing enabled", "otlp_endpoint", cfg.OTLPEndpoint)
	}

	db, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("database connect failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	cipher, err := crypto.New(cfg.KMSKeyName, cfg.SecretMasterKey, log)
	if err != nil {
		log.Error("crypto init failed", "err", err)
		os.Exit(1)
	}
	vault := connector.NewVault(cipher) // ADR-0004 credential vault

	blobs, err := blobstore.New(cfg.GCSBucket, cfg.BlobDir) // ADR-0002/0005 evidence store
	if err != nil {
		log.Error("blobstore init failed", "err", err)
		os.Exit(1)
	}
	log.Info("blobstore ready", "backend", blobs.Backend())

	tokens := auth.NewManager(cfg.JWTSecret, cfg.JWTIssuer, cfg.AccessTTL)
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

	// --- domain wiring (entity -> repo -> service -> handler) ---
	tenantSvc := tenant.NewService(tenant.NewRepository(db))
	tenantH := tenant.NewHandler(tenantSvc)

	iamSvc := iam.NewService(iam.NewRepository(db), db, tokens, cipher)
	iamH := iam.NewHandler(iamSvc)

	// SSO (OIDC): per-tenant IdP connections + JIT provisioning (§6.2 IAM-001).
	ssoSvc := sso.NewService(sso.NewRepository(db), sso.NewClient(), cipher, iamSvc, tokens, db, cfg.JWTSecret)
	ssoH := sso.NewHandler(ssoSvc)

	// SAML 2.0 SSO (§6.2 IAM-001). Signed-assertion validation via gosaml2.
	samlSvc := sso.NewSAMLService(sso.NewSAMLRepository(db), iamSvc, tokens, db, cfg.JWTSecret)
	samlH := sso.NewSAMLHandler(samlSvc)

	alertSvc := alert.NewService(alert.NewRepository(db))
	alertH := alert.NewHandler(alertSvc)

	detectionRepo := detection.NewRepository(db)
	detEngine := detection.NewEngine(detectionRepo)
	detectionH := detection.NewHandler(detection.NewService(detectionRepo, detEngine))

	notifySvc := notify.NewService(log)
	notifyH := notify.NewHandler(notifySvc)

	// Outbound ticketing (ServiceNow/Jira) — mirrors incidents to the tenant's ITSM.
	ticketingSvc := ticketing.NewService(ticketing.NewRepository(db), cipher)
	ticketingH := ticketing.NewHandler(ticketingSvc)

	incidentSvc := incident.NewService(incident.NewRepository(db), alertSvc, notifySvc).
		WithAssignees(iamSvc).WithTicketer(ticketingSvc)
	incidentH := incident.NewHandler(incidentSvc)

	billingSvc := billing.NewService(billing.NewRepository(db))
	billingH := billing.NewHandler(billingSvc)

	tiRepo := threatintel.NewRepository(db)
	enricher := threatintel.NewEnricher(tiRepo)
	threatH := threatintel.NewHandler(threatintel.NewService(tiRepo, enricher))

	ingestSvc := ingestion.NewService(ingestion.NewRepository(db), jobs, billingSvc, blobs)
	ingestH := ingestion.NewHandler(ingestSvc, events)

	connectorH := connector.NewHandler(connector.NewService(connector.NewRepository(db), vault, ingestSvc))
	soarH := soar.NewHandler(soar.NewService(soar.NewRepository(db)))
	aiH := ai.NewHandler(ai.NewService(ai.NewGateway(cfg.AnthropicAPIKey, cfg.AIModel), alertSvc, db))
	reportingH := reporting.NewHandler(reporting.NewService(db, events))
	complianceH := compliance.NewHandler()

	// --- bootstrap first-run provider tenant + platform admin ---
	bootstrap(ctx, log, tenantSvc, iamSvc, cfg.BootstrapEmail, cfg.BootstrapPassword)

	// --- routing ---
	authn := auth.Authenticate(tokens)
	providerRoles := []auth.Role{
		auth.RolePlatformAdmin, auth.RoleSOCManager,
		auth.RoleAnalystT1, auth.RoleAnalystT2, auth.RoleAnalystT3, auth.RoleDetectionEng,
	}
	// Rate limits. In-memory (per-instance) by default; global across replicas when
	// NIRVET_REDIS_ADDR is set (reviewer: introduce Redis at first horizontal scale-out).
	var redisClient *redis.Client
	if cfg.RedisAddr != "" {
		redisClient = redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
		if err := redisClient.Ping(ctx).Err(); err != nil {
			log.Error("redis ping failed", "err", err)
			os.Exit(1)
		}
		defer func() { _ = redisClient.Close() }()
		log.Info("rate limiting backend", "backend", "redis", "addr", cfg.RedisAddr)
	}
	loginLimit := ratelimit.Middleware(ratelimit.Build(redisClient, 0.2, 8, "login"), ratelimit.ByIP)     // ~1 login / 5s / IP, burst 8
	apiLimit := ratelimit.Middleware(ratelimit.Build(redisClient, 50, 100, "api"), ratelimit.ByPrincipal) // 50 rps / principal
	auditMut := audit.Mutations(db)                                                                       // record successful mutations (NFR-003)
	authed := func(h http.HandlerFunc) http.Handler { return httpx.Chain(h, authn, apiLimit, auditMut) }
	provider := func(h http.HandlerFunc) http.Handler {
		return httpx.Chain(h, authn, apiLimit, auditMut, auth.RequireRole(providerRoles...))
	}
	padmin := func(h http.HandlerFunc) http.Handler {
		return httpx.Chain(h, authn, apiLimit, auditMut, auth.RequireRole(auth.RolePlatformAdmin))
	}
	detEng := func(h http.HandlerFunc) http.Handler {
		return httpx.Chain(h, authn, apiLimit, auditMut, auth.RequireRole(auth.RolePlatformAdmin, auth.RoleSOCManager, auth.RoleDetectionEng))
	}
	// SSO connections are managed by the tenant's own admin or a platform admin.
	ssoAdmin := func(h http.HandlerFunc) http.Handler {
		return httpx.Chain(h, authn, apiLimit, auditMut, auth.RequireRole(auth.RolePlatformAdmin, auth.RoleCustomerAdmin))
	}

	mux := http.NewServeMux()
	// health
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "nirvet-api"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := db.Health(r.Context()); err != nil {
			httpx.JSON(w, http.StatusServiceUnavailable, map[string]string{"status": "db_unavailable"})
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	// Prometheus scrape endpoint (unauthenticated, for the metrics collector).
	mux.Handle("GET /metrics", metrics.Handler())
	// API reference (unauthenticated): raw spec + Swagger UI.
	mux.Handle("GET /openapi.yaml", api.SpecHandler())
	mux.Handle("GET /docs", api.DocsHandler())
	// auth + self
	mux.Handle("POST /auth/login", httpx.Chain(http.HandlerFunc(iamH.Login), loginLimit))
	// SSO (OIDC) — public login start/callback (rate-limited like login).
	mux.Handle("GET /auth/sso/start", httpx.Chain(http.HandlerFunc(ssoH.Start), loginLimit))
	mux.Handle("GET /auth/sso/callback", httpx.Chain(http.HandlerFunc(ssoH.Callback), loginLimit))
	// SSO connection management (tenant admin / platform admin).
	mux.Handle("POST /admin/sso", ssoAdmin(ssoH.CreateConnection))
	mux.Handle("GET /admin/sso", ssoAdmin(ssoH.ListConnections))
	mux.Handle("DELETE /admin/sso/{id}", ssoAdmin(ssoH.DeleteConnection))
	// SAML 2.0 — public SP-initiated start + ACS (rate-limited); admin connection mgmt.
	mux.Handle("GET /auth/sso/saml/start", httpx.Chain(http.HandlerFunc(samlH.Start), loginLimit))
	mux.Handle("POST /auth/sso/saml/acs", httpx.Chain(http.HandlerFunc(samlH.ACS), loginLimit))
	mux.Handle("POST /admin/sso/saml", ssoAdmin(samlH.CreateConnection))
	mux.Handle("GET /admin/sso/saml", ssoAdmin(samlH.ListConnections))
	mux.Handle("DELETE /admin/sso/saml/{id}", ssoAdmin(samlH.DeleteConnection))
	// Outbound ticketing (ServiceNow/Jira) connection management.
	mux.Handle("POST /admin/ticketing", ssoAdmin(ticketingH.Create))
	mux.Handle("GET /admin/ticketing", ssoAdmin(ticketingH.List))
	mux.Handle("DELETE /admin/ticketing/{id}", ssoAdmin(ticketingH.Delete))
	mux.Handle("GET /me", authed(iamH.Me))
	mux.Handle("POST /mfa/enroll", authed(iamH.EnrollMFA))
	mux.Handle("POST /mfa/activate", authed(iamH.ActivateMFA))
	mux.Handle("POST /mfa/disable", authed(iamH.DisableMFA))
	// platform admin
	mux.Handle("POST /admin/tenants", padmin(tenantH.Create))
	mux.Handle("GET /admin/tenants", padmin(tenantH.List))
	mux.Handle("GET /admin/tenants/{id}", padmin(tenantH.Get))
	mux.Handle("POST /admin/users", padmin(iamH.Create))
	// ingestion (any authenticated principal for the scaffold)
	mux.Handle("POST /ingest", authed(ingestH.Ingest))
	mux.Handle("GET /events", provider(ingestH.Events))
	// alerts (SOC)
	mux.Handle("GET /alerts", provider(alertH.List))
	mux.Handle("GET /alerts/{id}", provider(alertH.Get))
	mux.Handle("POST /alerts/{id}/assign", provider(alertH.Assign))
	mux.Handle("POST /alerts/{id}/promote", provider(incidentH.PromoteFromAlert))
	mux.Handle("POST /alerts/{id}/summarise", provider(aiH.SummariseAlert))
	// detection engineering
	mux.Handle("GET /detections", provider(detectionH.List))
	mux.Handle("POST /detections", detEng(detectionH.Create))
	mux.Handle("POST /detections/import/sigma", detEng(detectionH.ImportSigma))
	mux.Handle("POST /detections/cel", detEng(detectionH.CreateCEL))
	mux.Handle("POST /detections/{id}/enabled", detEng(detectionH.SetEnabled))
	// connectors
	mux.Handle("GET /connectors/catalogue", provider(connectorH.Catalogue))
	mux.Handle("GET /connectors", provider(connectorH.List))
	mux.Handle("POST /connectors", provider(connectorH.Create))
	mux.Handle("DELETE /connectors/{id}", provider(connectorH.Delete))
	// public webhook ingestion (source-key authenticated, per-IP rate limited)
	webhookLimit := ratelimit.Middleware(ratelimit.Build(redisClient, 50, 100, "webhook"), ratelimit.ByIP)
	mux.Handle("POST /ingest/webhook/{id}", httpx.Chain(http.HandlerFunc(connectorH.Webhook), webhookLimit))
	// SOAR (playbooks, runs, approvals, authority-to-act)
	mux.Handle("GET /playbooks", provider(soarH.ListPlaybooks))
	mux.Handle("POST /playbooks/{id}/run", provider(soarH.Run))
	mux.Handle("GET /soar/runs", provider(soarH.ListRuns))
	mux.Handle("GET /soar/runs/{id}", provider(soarH.GetRun))
	mux.Handle("POST /soar/runs/{id}/approve", provider(soarH.Approve))
	mux.Handle("POST /soar/runs/{id}/reject", provider(soarH.Reject))
	mux.Handle("POST /soar/authority", padmin(soarH.SetAuthority))
	// threat intelligence (watchlist)
	mux.Handle("GET /threat-intel", provider(threatH.List))
	mux.Handle("POST /threat-intel", provider(threatH.Add))
	// reporting
	mux.Handle("GET /reports/summary", provider(reportingH.SummaryHTTP))
	// compliance
	mux.Handle("GET /compliance/coverage", provider(complianceH.Coverage))
	// billing / entitlements
	mux.Handle("GET /billing/entitlements", provider(billingH.Get))
	mux.Handle("PUT /billing/entitlements", padmin(billingH.Set))
	// notifications
	mux.Handle("POST /notify/test", provider(notifyH.Test))
	// incidents (SOC)
	mux.Handle("GET /incidents", provider(incidentH.List))
	mux.Handle("GET /incidents/{id}", provider(incidentH.Get))
	mux.Handle("POST /incidents/{id}/assign", provider(incidentH.Assign))
	mux.Handle("POST /incidents/{id}/notes", provider(incidentH.AddNote))
	mux.Handle("POST /incidents/{id}/close", provider(incidentH.Close))

	handler := httpx.Chain(mux, httpx.RequestID, httpx.Recover(log), httpx.CORS(cfg.CORSOrigin), tracing.Middleware(), metrics.Middleware(), httpx.AccessLog(log))

	// --- inline ingest worker (dev convenience; prod runs cmd/worker) ---
	workerCtx, stopWorker := context.WithCancel(ctx)
	defer stopWorker()
	if cfg.InlineWorker {
		wk := ingestion.NewWorker(jobs, events, enricher, detEngine, alertSvc, log)
		go wk.Start(workerCtx, time.Second)
		poller := connector.NewPoller(connector.NewRepository(db), vault, ingestSvc, log)
		go poller.Start(workerCtx, time.Minute)
		log.Info("inline ingest worker + connector poller started")
	}

	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}()
	log.Info("nirvet api listening", "addr", cfg.HTTPAddr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info("shutting down")
	stopWorker()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

// bootstrap creates the provider tenant and a platform admin on first run.
func bootstrap(ctx context.Context, log *slog.Logger, tenantSvc *tenant.Service, iamSvc *iam.Service, email, password string) {
	tenants, err := tenantSvc.List(ctx)
	if err != nil {
		log.Warn("bootstrap skipped (db not ready/migrated?)", "err", err)
		return
	}
	if len(tenants) > 0 {
		return
	}
	t, err := tenantSvc.Create(ctx, tenant.CreateInput{
		Name: "Nirvet Provider", Sector: "mssp", Country: "GB",
		ServiceTier: tenant.TierEnterprise, IsolationTier: tenant.IsolationPooled,
	})
	if err != nil {
		log.Warn("bootstrap: create provider tenant failed", "err", err)
		return
	}
	if _, err := iamSvc.Create(ctx, t.ID, iam.CreateInput{Email: email, Password: password, Role: auth.RolePlatformAdmin}); err != nil {
		log.Warn("bootstrap: create admin failed", "err", err)
		return
	}
	log.Info("bootstrap: provider tenant + platform admin created", "tenant_id", t.ID, "admin_email", email)
}
