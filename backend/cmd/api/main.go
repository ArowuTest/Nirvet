// Command api is the Nirvet platform HTTP API. It wires the platform foundation
// (config, db+RLS, auth, crypto, eventstore, queue) to the domain modules and
// serves the SOC value loop: tenant -> user/login -> ingest -> alert -> incident.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/netutil"

	"github.com/ArowuTest/nirvet/api"
	"github.com/ArowuTest/nirvet/internal/ai"
	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/billing"
	"github.com/ArowuTest/nirvet/internal/branding"
	"github.com/ArowuTest/nirvet/internal/compliance"
	"github.com/ArowuTest/nirvet/internal/connector"
	"github.com/ArowuTest/nirvet/internal/correlation"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/entitygraph"
	"github.com/ArowuTest/nirvet/internal/evidence"
	"github.com/ArowuTest/nirvet/internal/fleet"
	"github.com/ArowuTest/nirvet/internal/iam"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/investigation"
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
	"github.com/ArowuTest/nirvet/internal/platformadmin"
	"github.com/ArowuTest/nirvet/internal/posture"
	"github.com/ArowuTest/nirvet/internal/postureproj"
	"github.com/ArowuTest/nirvet/internal/readmodel"
	"github.com/ArowuTest/nirvet/internal/reporting"
	"github.com/ArowuTest/nirvet/internal/retention"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/soarwire"
	"github.com/ArowuTest/nirvet/internal/sso"
	"github.com/ArowuTest/nirvet/internal/syslogd"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/ArowuTest/nirvet/internal/threatintel"
	"github.com/ArowuTest/nirvet/internal/ticketing"
	"github.com/ArowuTest/nirvet/internal/vulnerability"
	"github.com/redis/go-redis/v9"
)

// RBAC route tiers (R2 H-D/M-D). provider = any SOC role incl. analyst_t1 (reads +
// triage/assign/note). senior = destructive/sensitive routes T1 must not reach. manager
// = platform_admin + soc_manager only (asset criticality writes). Package-level so the
// membership invariant is regression-tested (main_test.go).
var (
	providerRoles = auth.ProviderRoles() // single source of truth (auth.IsProviderRole gates the same set —
	//                                       so the fleet route gate and the resolver scope gate cannot diverge)
	seniorRoles  = auth.SeniorRoles() // single source of truth (auth.IsSenior gates the same set)
	managerRoles = []auth.Role{auth.RolePlatformAdmin, auth.RoleSOCManager}
)

// httpMaxConns caps concurrent API connections (M-4 DoS backstop). Tunable at the deployment layer.
const httpMaxConns = 2048

// cipherSecretBox adapts crypto.SecretCipher to the ai.SecretBox interface (Seal/Open) — AI provider API
// keys are a distinct secret class from connector credentials, so they don't go through the connector vault.
type cipherSecretBox struct{ c crypto.SecretCipher }

func (b cipherSecretBox) Seal(scope uuid.UUID, pt []byte) ([]byte, error) {
	return b.c.Encrypt(scope, pt)
}
func (b cipherSecretBox) Open(scope uuid.UUID, ct []byte) ([]byte, error) {
	return b.c.Decrypt(scope, ct)
}

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
	// Fail-closed backstop: refuse to serve if the runtime DB role can bypass RLS (superuser / BYPASSRLS / owns
	// RLS tables via owner_bypass). Isolation depends on connecting as the non-owner nirvet_app role; a
	// misconfigured NIRVET_DATABASE_URL must crash loudly, not silently disable cross-tenant isolation.
	if err := db.AssertRLSConstrainedRole(ctx); err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(1)
	}

	cipher, err := crypto.New(cfg.KMSKeyName, cfg.SecretMasterKey, log)
	if err != nil {
		log.Error("crypto init failed", "err", err)
		os.Exit(1)
	}
	vault := connector.NewVault(cipher).WithDB(db) // ADR-0004 credential vault (GC-1: Open audits decrypts)

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
	cookieOpts := auth.DefaultCookieOpts(cfg.IsProduction()) // ADR-0007 session cookies (Secure in prod)
	// Where a completed SSO login lands the browser (the SPA console). Derived from the configured SPA origin.
	appConsoleURL := strings.TrimRight(cfg.CORSOrigin, "/") + "/console"
	iamH := iam.NewHandler(iamSvc, cookieOpts)

	// SSO (OIDC): per-tenant IdP connections + JIT provisioning (§6.2 IAM-001).
	ssoSvc := sso.NewService(sso.NewRepository(db), sso.NewClient(), cipher, iamSvc, tokens, db, string(auth.DeriveKey(cfg.JWTSecret, "sso-state")))
	ssoH := sso.NewHandler(ssoSvc, cookieOpts, appConsoleURL)

	// SAML 2.0 SSO (§6.2 IAM-001). Signed-assertion validation via gosaml2.
	samlSvc := sso.NewSAMLService(sso.NewSAMLRepository(db), iamSvc, tokens, db, string(auth.DeriveKey(cfg.JWTSecret, "saml-state")))
	samlH := sso.NewSAMLHandler(samlSvc, cookieOpts, appConsoleURL)

	alertSvc := alert.NewService(alert.NewRepository(db))
	alertH := alert.NewHandler(alertSvc)
	auditH := audit.NewHandler(db)
	// Operator fleet console (Ghana operator seam #1/#3): bounded cross-tenant alert read + write. Scope is
	// resolved from the principal (provider → whole instance; non-provider → empty); MA-1 SD-fn enforces the
	// read bound; writes resolve the target from the resource, check fleet scope, and audit in the target tenant.
	// The destructive (SOAR containment) path is attached below once soarSvc is wired (WithContainment).
	fleetSvc := fleet.NewService(db).WithAlerts(alertSvc)
	fleetH := fleet.NewHandler(fleetSvc)

	// Vendor posture oversight (Ghana operator seam #4, MA-4): metadata-only fleet health projection so the
	// vendor can spot a neglected issue WITHOUT a standing content read. posture is content-free by
	// construction (CI-guarded no-import-path); postureproj is the content→posture projection choke point.
	postureSvc := posture.NewService(db)
	postureH := posture.NewHandler(postureSvc)
	postureProjector := postureproj.NewProjector(db, postureSvc)
	// Oversight scope-resolver family: org-sub-admin + payer read the SAME MA-4 posture, scoped by grant. The
	// platform_admin administers the grants (issue/revoke, audited). Delegates are gated to the posture read;
	// their scope is resolved from their own grants (never a client-supplied id).
	grantH := posture.NewGrantHandler(posture.NewGrantService(db))
	// Syslog source provisioning (padmin): register/enable/disable/list the mTLS syslog sources the listener
	// attributes by cert fingerprint. Secure default: a new source is disabled until explicitly enabled.
	syslogAdminH := syslogd.NewAdminHandler(syslogd.NewSourceStore(db))
	// White-label branding (Ghana operator L): instance-level presentation config (operator name/logo/color),
	// PUBLIC read for the login page, padmin write. Not per-tenant; never touches tenant isolation.
	brandingH := branding.NewHandler(branding.NewService(db))

	// Alert correlation + risk scoring (§6.7): risk-ranked clusters of related alerts.
	correlationSvc := correlation.NewService(correlation.NewRepository(db))
	correlationH := correlation.NewHandler(correlationSvc)

	detectionRepo := detection.NewRepository(db)
	detEngine := detection.NewEngine(detectionRepo).WithLogger(log)
	detectionSvc := detection.NewService(detectionRepo, detEngine)
	detectionH := detection.NewHandler(detectionSvc)
	// Close the DET-007 loop: an alert disposition feeds detection tuning (alert stays decoupled).
	alertSvc.WithFeedbackSink(detectionSvc)

	// Durable notification outbox: notifications are enqueued transactionally and
	// delivered by a background dispatcher with retry (R3 §6.5 — no silent drop).
	outboxRepo := notify.NewOutboxRepository(db)
	notifySvc := notify.NewService(log).WithOutbox(outboxRepo).
		WithSenders(notify.NewSenderRepo(db), cipher, notify.DefaultSMSClient()). // §6.16 email/SMS via per-tenant sender config
		WithTemplates(notify.NewTemplateRepo(db)).                                // §6.16 templates + throttle/localization
		WithLinkKey(auth.DeriveKey(cfg.JWTSecret, "notify-link"))                 // §6.16 secure expiring links (HMAC, key-separated)
	notifyH := notify.NewHandler(notifySvc)
	inboxH := notify.NewInboxHandler(notify.NewInbox(db)) // §6.16 per-user in-app feed
	// Break-glass access fires an automatic alert (§6.2 IAM-006).
	iamSvc.WithAlerter(notifySvc)
	// G1 admin-issued password reset: link base URL = the frontend origin; email delivery via the outbox.
	iamSvc.WithResetBaseURL(cfg.CORSOrigin).WithResetMailer(notifySvc)

	// Outbound ticketing (ServiceNow/Jira) — mirrors incidents to the tenant's ITSM.
	ticketingSvc := ticketing.NewService(ticketing.NewRepository(db), cipher)
	ticketingH := ticketing.NewHandler(ticketingSvc)

	incidentSvc := incident.NewService(incident.NewRepository(db), alertSvc, notifySvc).
		WithAssignees(iamSvc).WithTicketer(ticketingSvc).WithEnqueuer(outboxRepo).WithEscalation(tenantSvc).WithSLA(tenantSvc).WithBlobStore(blobs)
	incidentH := incident.NewHandler(incidentSvc)
	// Customer read-side (Slice A): the audience-projection chokepoint. THE ONLY handler wired to the customer/
	// oversight read chains — a raw entity never reaches a customer principal (check-audience-projection.sh).
	custReadH := readmodel.NewHandler(incidentSvc, alertSvc, readmodel.NewPolicyStore(db), readmodel.NewRegulatorRepo(db), postureSvc, db)
	// High-risk correlation clusters auto-open an incident (§6.7); window/thresholds are the
	// tenant's admin-configurable correlation policy (Phase 0-D no-hardcoding).
	correlationSvc.WithIncidenter(incidentSvc).WithPolicy(tenantSvc)

	// Asset inventory (§6.15): tenant-scoped assets with business criticality.
	assetSvc := asset.NewService(asset.NewRepository(db), db)
	assetH := asset.NewHandler(assetSvc)
	// A critical affected asset escalates incident severity + tightens SLA (§6.8/§6.15).
	incidentSvc.WithAssetContext(assetSvc)

	// Vulnerability & exposure (§6.15 slice 2): open vulns mapped to assets by ref.
	vulnSvc := vulnerability.NewService(vulnerability.NewRepository(db))
	vulnH := vulnerability.NewHandler(vulnSvc)

	// Entity graph (§6.9): read-only blast-radius view composing alerts/incidents/
	// correlations/asset for an entity ref.
	egSvc := entitygraph.NewService(alertSvc, incidentSvc, correlationSvc, assetSvc)
	entityGraphH := entitygraph.NewHandler(egSvc)

	// Evidence-pack signing key (R2 H-B): a persistent Ed25519 seed from config, else an
	// ephemeral per-process key in dev (packs are still really signed, just not verifiable
	// across a restart — production requires the key via config guard).
	var evidenceSigner ed25519.PrivateKey
	if cfg.EvidenceSigningKey != "" {
		seed, derr := base64.StdEncoding.DecodeString(cfg.EvidenceSigningKey)
		if derr != nil || len(seed) != ed25519.SeedSize {
			log.Error("evidence signing key invalid: need a base64 32-byte Ed25519 seed")
			os.Exit(1)
		}
		evidenceSigner = ed25519.NewKeyFromSeed(seed)
	} else {
		if _, evidenceSigner, err = ed25519.GenerateKey(rand.Reader); err != nil {
			log.Error("evidence signer keygen failed", "err", err)
			os.Exit(1)
		}
		log.Warn("evidence signing key not set — using an ephemeral key; exported packs cannot be verified across restarts")
	}
	// Evidence-pack export (§6.13): composes case + alert + event + asset + audit reads,
	// with an Ed25519 signature over the pack digest (R2 H-B).
	evidenceH := evidence.NewHandler(evidence.NewService(incidentSvc, alertSvc, events, assetSvc, vulnSvc, db, evidenceSigner))

	billingSvc := billing.NewService(billing.NewRepository(db)).WithAlerter(alertSvc) // §6.17 slice B: HIGH alert on account suspend
	billingH := billing.NewHandler(billingSvc)

	tiRepo := threatintel.NewRepository(db)
	enricher := threatintel.NewEnricher(tiRepo)
	threatH := threatintel.NewHandler(threatintel.NewService(tiRepo, enricher))

	ingestSvc := ingestion.NewService(ingestion.NewRepository(db), jobs, billingSvc, blobs)
	ingestH := ingestion.NewHandler(ingestSvc, events)
	// §6.5: normalization data-quality recorder (shared with the embedded worker) + dashboard.
	normQ := ingestion.NewNormQuality(db)
	normH := ingestion.NewNormHandler(normQ)

	connSvc := connector.NewService(connector.NewRepository(db), vault, ingestSvc).
		WithEscalation(tenantSvc). // #188 cred-expiry reminders route to the tenant escalation matrix...
		WithEnqueuer(outboxRepo)   // ...and queue durably on the notify outbox
	connectorH := connector.NewHandler(connSvc)
	// SOAR resolves authority-to-act per action from the tenant's authority_policies
	// (single source of truth; Phase 0 reconciliation — replaces tenants.authority_mode).
	// SOAR action executors (§6.11): notify actions run for real via the durable outbox; connector
	// containment actions simulate until the live Actioner registry exists (the seam is ready).
	soarExecs := soar.NewExecutors().
		Register("notify_analyst", soar.NewNotifyExecutor(outboxRepo)).
		Register("notify_customer", soar.NewNotifyExecutor(outboxRepo))
	soarRepo := soar.NewRepository(db)
	// #187 slice C: real internal, non-destructive executors (create_note/create_ticket/add_watchlist/
	// collect_evidence/enrich) — each writes a durable tenant-scoped soar_action_records row inside the run tx.
	internalRec := soar.NewInternalRecorder(soarRepo)
	for _, k := range soar.InternalActionKeys() {
		soarExecs.Register(k, internalRec)
	}
	soarSvc := soar.NewService(soarRepo).WithAuthorizer(tenantSvc).WithExecutors(soarExecs)
	// §6.11 slice B/C: wire the two-phase supervisor. The Actioner registry starts EMPTY — real vendor
	// containment actions (Defender isolate/release, Entra disable, PAN block) register incrementally
	// (registration, not an engine change), and stay dormant until a tenant enables destructive actions.
	// With no registered Actioner, every connector step keeps the truthful-simulation slice-A behavior.
	// The CredDecryptor (slice C) vault-decrypts a tenant's connector creds for Phase B.
	soarCreds := connector.NewCredentialResolver(connector.NewRepository(db), vault)
	// §6.11 slice C: register the real Defender isolate/release Actioners (prod endpoints; SafeClient).
	// The supervised path now engages for a Defender isolate step, but ONLY when the tenant has enabled
	// destructive actions (soar_settings.destructive_enabled, default OFF) — otherwise the gate withholds
	// before any external call. Empty endpoints select production defaults (per-tenant token URL, MDE host).
	soarReg := soar.NewActionerRegistry()
	for _, a := range connector.NewDefenderActioner("", "", "", nil).Actioners() {
		soarReg.Register(a)
	}
	for _, a := range connector.NewEntraActioner("", "", "", nil).Actioners() { // §6.11 vendor-2: identity containment
		soarReg.Register(a)
	}
	// A destructive step initiated via a playbook run/approve also goes through this supervisor, so it carries
	// the same D5 protected-identity guard (blast-radius) + the failed/withheld-containment alerter.
	soarSvc.WithSupervisor(soar.NewSupervisor(soarRepo, soarReg, soarCreds, log).
		WithAlerter(soarwire.NewContainmentAlerter(alertSvc, outboxRepo)).
		WithGuard(connector.NewEntraProtectedGuard(soarRepo, "", "", "", nil)). // D5 identity net
		WithGuard(connector.NewHostProtectedGuard(soarRepo, "", "", "", nil)))  // D5 host net (M3; resolves to canonical machine id)
	// #188 customer-approval: re-validate a recorded internal approver is still active at execution time (a stale
	// approval by a since-disabled user cannot fire a destructive action).
	soarSvc.WithApproverValidator(approverActiveAdapter{iam: iamSvc})
	soarH := soar.NewHandler(soarSvc)
	// Fleet destructive path (Ghana operator seam #3): a fleet operator fires/approves a SOAR containment on
	// a target tenant's alert. RunForTarget/ApproveForTarget evaluate per-target authority in the target's
	// context and land the effect + audit durably in the target via this same supervisor. *soar.Service
	// satisfies fleet.ContainmentRunner. (Same *fleetSvc pointer the handler above already holds.)
	fleetSvc.WithContainment(soarSvc)
	aiSvc := ai.NewService(ai.NewGateway(cfg.AnthropicAPIKey, cfg.AIModel), alertSvc, db)
	// AI incident triage composes incident + asset context (§6.12, assistive-only).
	aiSvc.WithIncidentContext(incidentSvc, assetSvc)
	// §6.12 #117 A-5: resolve the tenant's configured provider per call (anthropic / openai_compatible / disabled),
	// fail-closed. The global anthropic seed keeps current behavior; api keys unseal through the same vault.
	// AI provider API keys are a SEPARATE secret class from connector credentials, so they seal/unseal through
	// a cipher-backed box (not the audited connector vault, whose Open is connector-credential-specific, GC-1).
	aiBox := cipherSecretBox{cipher}
	aiSvc.WithResolver(ai.NewResolver(ai.NewRepository(db), cfg.AnthropicAPIKey, cfg.AIModel, ai.NewVaultKeyResolver(aiBox)))
	// §6.12 #188 AI-egress redaction: mask customer PII/secrets before they leave to a third-party LLM. mask-by-
	// default (balanced) — the resolver reads the tenant's policy + config-extensible patterns; even unwired it
	// masks via the built-in floor. Wired into the service so the completeExternal chokepoint applies it.
	redactionSvc := ai.NewRedactionService(db)
	aiSvc.WithRedaction(redactionSvc)
	redactionH := ai.NewRedactionHandler(redactionSvc)
	aiH := ai.NewHandler(aiSvc)
	// §6.12 #117 admin-configurable AI providers: config surface (global default + per-tenant override + platform
	// allowlist + tenant policy). The vault (line 107) seals api keys; the allowlist is the data-egress/residency
	// boundary. DORMANT — the seeded global anthropic row keeps current behavior until an admin changes it.
	aiCfgH := ai.NewConfigHandler(ai.NewConfigService(ai.NewRepository(db), aiBox))
	// §6.12 AI governance slice A: prompt registry + eval harness (padmin content) + output feedback (analyst).
	// The eval runner is deterministic/hermetic (no provider needed); the llm judge is dormant until slice B.
	aiGovH := ai.NewGovernanceHandler(ai.NewGovernanceService(ai.NewGovRepo(db)))
	// §6.18 #122 platform-admin: safety-classed feature flags, tenant lifecycle (legal hold / uniform offboarding),
	// maintenance windows. The safety gates (immutable/protected/four-eyes, legal-hold-blocks-delete, critical-breaks-
	// through) live in the services; the handler is thin plumbing. All routes are padmin-gated below.
	padminRepo := platformadmin.NewRepository(db)
	padminH := platformadmin.NewHandler(
		platformadmin.NewService(padminRepo, alertSvc).WithSessionRevoker(iamSvc), // offboard kills the tenant's sessions
		platformadmin.NewMaintenanceService(padminRepo),
	)
	// §6.9 #124 investigation surface. The hunt-query engine is allow-list-compiles-to-bound-params (the codebase's
	// first user-predicate surface); RLS-under-WithTenant is the backstop; every query/entity-read is read-audited.
	// The entity profile+pivot (I-3) composes the existing entitygraph service (tenant-scoped) — no cross-tenant reach.
	invRepo := investigation.NewRepository(db)
	investigationH := investigation.NewHandler(
		// #188 multi-lane case timeline: merge the forensic event lane with the incident journal (analyst/
		// automation/comms/evidence) via a narrow adapter, keeping investigation decoupled from incident.
		investigation.NewService(invRepo).WithCaseJournal(caseJournalAdapter{inc: incidentSvc}).WithRawStore(blobs), // #188 raw-event fetch
		investigation.NewEntityService(egSvc, invRepo),
		// I-5 data-gap panel: unify detection coverage gaps + host-source silence + normalization drift (all tenant-scoped).
		investigation.NewDataGapService(detectionSvc, normQ, connector.NewRepository(db)),
	)
	reportingSvc := reporting.NewService(db, events)
	reportingH := reporting.NewHandler(reportingSvc)
	// §6.13 #125 report export (JSON/CSV/XLSX). Generation under WithTenant + hard caps; formula-injection neutralized
	// at the serializer; download is a session-authorized GET (not a bearer link); every generate/download audited.
	// #188 regulatory breach report reads incident content through a narrow adapter (reporting stays decoupled from
	// the incident package — no import cycle; the reader runs under WithTenant so RLS confines it).
	reportExportH := reporting.NewReportHandler(
		reporting.NewReportService(reporting.NewReportRepository(db), blobs, reportingSvc).
			WithBreachSource(breachIncidentAdapter{inc: incidentSvc}).
			WithSigner(evidenceSigner)) // #188: sign the regulatory breach report (same key as evidence packs)
	// §6.14 #188 retention enforcement (the data-deleter). Safe default: policy DISABLED = dry-run/report-only
	// until a tenant explicitly enables live deletion; legal-hold always preserves; deletes raw_events (+ payload
	// blob) + events only; ClickHouse ages out via its own TTL.
	retentionSvc := retention.NewService(db, blobs)
	retentionH := retention.NewHandler(retentionSvc)
	complianceH := compliance.NewHandler(compliance.NewService(compliance.NewRepository(db)))

	// --- bootstrap first-run provider tenant + platform admin ---
	bootstrap(ctx, log, tenantSvc, iamSvc, cfg.BootstrapEmail, cfg.BootstrapPassword)

	// --- routing ---
	// Authn accepts a JWT or a service-account API key (nvt_…) — the resolved Principal is
	// identical downstream, so RBAC + RLS + audit apply unchanged (§6.2 IAM-001) — and then
	// enforces the tenant's session policy (IP allow-list, §6.2 IAM-007) on that Principal.
	authn := auth.AuthenticateFull(tokens, iamSvc, iamSvc, cfg.TrustedProxyDepth)
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
	// Login is throttled per client IP (X-Forwarded-For spoof-resistant via trusted-proxy
	// depth). The IP limiter fails OPEN on a Redis outage (availability); the durable,
	// fail-closed brute-force control is the DB-backed per-account lockout in iam.Login.
	loginLimit := ratelimit.Middleware(ratelimit.Build(redisClient, 0.2, 8, "login"), ratelimit.ByIPTrusting(cfg.TrustedProxyDepth)) // ~1 login / 5s / IP, burst 8
	apiLimit := ratelimit.Middleware(ratelimit.Build(redisClient, 50, 100, "api"), ratelimit.ByPrincipal)                            // 50 rps / principal
	// AI copilot calls hit the LLM gateway (latency + token cost), so they get their own
	// much tighter per-principal bucket instead of sharing the 50-rps API allowance — a
	// compromised or runaway T1 token can't rack up gateway spend (R3 AI-rate). Separate
	// namespace ("ai"), so it does not interact with the general api bucket.
	aiLimit := ratelimit.Middleware(ratelimit.Build(redisClient, 0.5, 5, "ai"), ratelimit.ByPrincipal) // ~1 AI call / 2s / principal, burst 5
	auditMut := audit.Mutations(db)                                                                    // record successful mutations (NFR-003)
	// §6.17 slice B: a billing-suspended tenant's non-management users are blocked at the authenticated API
	// (bsuspend). ingest/detection/alerting never use these chains, so a suspended tenant keeps being protected;
	// platform-management (platform_admin/soc_manager) is exempt inside AccessGate so it can still manage the
	// suspended tenant. See account.go:AccessGate.
	bsuspend := billing.AccessGate(billingSvc)
	// interactive is the ONE builder for every authenticated, customer-facing chain. Baking bsuspend in here
	// (M-1 fix) means no interactive chain can silently omit the suspension gate — adding a route can only pick a
	// (limiter, roles) combination, never a chain without the gate. `lim` lets a chain swap in a tighter bucket
	// (e.g. the AI bucket). Only `padmin` (platform-only) is built outside this, and AccessGate exempts platform
	// staff anyway, so it needs no gate.
	interactive := func(lim httpx.Middleware, roles ...auth.Role) func(http.HandlerFunc) http.Handler {
		return func(h http.HandlerFunc) http.Handler {
			return httpx.Chain(h, authn, bsuspend, lim, auditMut, auth.RequireRole(roles...))
		}
	}
	// authed: any authenticated principal (no role floor), but still suspension-gated — a suspended tenant's
	// own users are blocked from general reads too.
	authed := func(h http.HandlerFunc) http.Handler { return httpx.Chain(h, authn, bsuspend, apiLimit, auditMut) }
	provider := interactive(apiLimit, providerRoles...)
	// aiProvider is the provider chain with the tight AI bucket swapped in for apiLimit — same roles (T1 keeps
	// assistive AI), stricter throughput (R3 AI-rate). Now also suspension-gated (M-1): a suspended tenant can no
	// longer keep burning AI-copilot spend.
	aiProvider := interactive(aiLimit, providerRoles...)
	// padmin is platform-admin only and intentionally NOT built from interactive: platform staff manage suspended
	// tenants (and AccessGate exempts them regardless), so this chain carries no suspension gate.
	padmin := func(h http.HandlerFunc) http.Handler {
		return httpx.Chain(h, authn, apiLimit, auditMut, auth.RequireRole(auth.RolePlatformAdmin))
	}
	detEng := interactive(apiLimit, auth.RolePlatformAdmin, auth.RoleSOCManager, auth.RoleDetectionEng)
	// oversight: the metadata-only posture read for the oversight family — platform_admin (whole instance) +
	// the scoped delegates (org-sub-admin, payer). resolveScope fail-closes any other principal to empty.
	oversight := interactive(apiLimit, auth.RolePlatformAdmin, auth.RoleOrgSubAdmin, auth.RolePayer)
	// SOAR approvals gate destructive automation, so they are restricted to senior roles (four-eyes is
	// additionally enforced in the service: requester != approver).
	soarApprover := interactive(apiLimit, auth.RolePlatformAdmin, auth.RoleSOCManager)
	// Playbook AUTHORING (#187) is a privileged control-plane action — a playbook drives real containment — so it
	// is gated to the same soc_manager+ floor as destructive approval. Authoring and approving are separate axes:
	// run-approval four-eyes (requester != approver) still holds, and the author cannot set the approval
	// requirement (catalog-governed), so a soc_manager who authors a playbook cannot self-approve its destructive
	// run. The service enforces this floor again defensively (defense-in-depth).
	soarAuthor := interactive(apiLimit, auth.RolePlatformAdmin, auth.RoleSOCManager)
	// senior = destructive/sensitive actions that a T1 (or a stolen T1 token) must not reach: connector
	// create/delete (creds / blind detection), playbook run, incident close, alert promote, threat-intel writes,
	// evidence-pack export (R2 H-D). T1 keeps reads + triage/assign/note + assistive AI.
	senior := interactive(apiLimit, seniorRoles...)
	// manager = platform_admin + soc_manager only. Asset writes set criticality that auto-escalates incident
	// severity + SLA, so they are restricted here (R2 M-D).
	manager := interactive(apiLimit, managerRoles...)
	// SSO connections are managed by the tenant's own admin or a platform admin.
	ssoAdmin := interactive(apiLimit, auth.RolePlatformAdmin, auth.RoleCustomerAdmin)
	// customerRead = the customer audience (customer_admin + customer_viewer). Only readmodel projection handlers
	// may be wired to this chain (enforced by scripts/check-audience-projection.sh); a provider handler here would
	// leak internal data to a customer principal.
	customerRead := interactive(apiLimit, auth.RoleCustomerAdmin, auth.RoleCustomerViewer)

	mux := http.NewServeMux()
	// health
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "nirvet-api"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		// Dependency-aware readiness (external-review): the DB and the telemetry event store are BOTH hard
		// dependencies — a query path that can't reach the event store is not ready even if the DB is up.
		deps := map[string]string{}
		ready := true
		if err := db.Health(r.Context()); err != nil {
			deps["database"] = "unavailable"
			ready = false
		} else {
			deps["database"] = "ok"
		}
		if err := events.Ping(r.Context()); err != nil {
			deps["event_store"] = "unavailable"
			ready = false
		} else {
			deps["event_store"] = "ok (" + esBackend + ")"
		}
		status, code := "ready", http.StatusOK
		if !ready {
			status, code = "not_ready", http.StatusServiceUnavailable
		}
		httpx.JSON(w, code, map[string]any{"status": status, "dependencies": deps})
	})
	// Prometheus scrape endpoint (unauthenticated, for the metrics collector).
	mux.Handle("GET /metrics", metrics.Handler())
	// API reference (unauthenticated): raw spec + Swagger UI.
	mux.Handle("GET /openapi.yaml", api.SpecHandler())
	mux.Handle("GET /docs", api.DocsHandler())
	// auth + self
	mux.Handle("POST /auth/login", httpx.Chain(http.HandlerFunc(iamH.Login), loginLimit))
	// ADR-0007 browser session: refresh rotates the access cookie; logout clears + revokes. Both authenticate by
	// the refresh cookie (no bearer), so they sit outside the authed chain, rate-limited like login.
	mux.Handle("POST /auth/refresh", httpx.Chain(http.HandlerFunc(iamH.Refresh), loginLimit))
	mux.Handle("POST /auth/logout", httpx.Chain(http.HandlerFunc(iamH.Logout), loginLimit))
	// Logout-everywhere (LOW #3): authenticated — bumps the user's session generation (kills live JWTs on all
	// devices) + revokes all refresh families. Needs a principal, so it sits on the authed chain.
	mux.Handle("POST /auth/logout-all", authed(iamH.LogoutAll))
	// Invitation acceptance (public, §6.2 IAM-001/008): the invitee sets a password. Rate-
	// limited like login since it provisions a user.
	mux.Handle("POST /auth/invitations/accept", httpx.Chain(http.HandlerFunc(iamH.AcceptInvitation), loginLimit))
	// G1 password reset: confirm is PUBLIC (token is the capability) + rate-limited per IP (RP-4).
	mux.Handle("POST /auth/password-reset/confirm", httpx.Chain(http.HandlerFunc(iamH.ConfirmPasswordReset), loginLimit))
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
	mux.Handle("POST /me/password", authed(iamH.ChangePassword))
	mux.Handle("POST /mfa/enroll", authed(iamH.EnrollMFA))
	mux.Handle("POST /mfa/activate", authed(iamH.ActivateMFA))
	mux.Handle("POST /mfa/disable", authed(iamH.DisableMFA))
	// Privileged elevation + break-glass (§6.2 IAM-004/006). Self-service request/break-glass/
	// mint; approval/reject/review + full list are manager-gated (four-eyes in the service).
	mux.Handle("POST /me/elevations", authed(iamH.RequestElevation))
	mux.Handle("GET /me/elevations", authed(iamH.ListMyElevations))
	mux.Handle("POST /me/elevations/break-glass", authed(iamH.BreakGlass))
	mux.Handle("POST /me/elevations/{id}/token", authed(iamH.MintElevatedToken))
	mux.Handle("GET /admin/elevations", manager(iamH.ListElevations))
	mux.Handle("POST /admin/elevations/{id}/approve", manager(iamH.ApproveElevation))
	mux.Handle("POST /admin/elevations/{id}/reject", manager(iamH.RejectElevation))
	mux.Handle("POST /admin/elevations/{id}/review", manager(iamH.ReviewElevation))
	// platform admin
	mux.Handle("POST /admin/tenants", padmin(tenantH.Create))
	// Bulk onboarding factory (Ghana launch long-pole): batch-create tenants, each via the same secure atomic
	// path; per-row result report; idempotent on external_ref. padmin-only.
	mux.Handle("POST /admin/tenants/batch", padmin(tenantH.CreateBatch))
	// Posture oversight read (MA-4 + oversight resolver family): metadata-only fleet health, scoped per role by
	// resolveScope — platform_admin → whole instance; org-sub-admin/payer → their granted tenants; else empty.
	mux.Handle("GET /posture/fleet", oversight(postureH.Fleet))
	// Oversight grant management (MA-OV-3): platform_admin issues/revokes org/payer grants (audited).
	mux.Handle("POST /admin/oversight/org-grants", padmin(grantH.GrantOrg))
	mux.Handle("DELETE /admin/oversight/org-grants", padmin(grantH.RevokeOrg))
	mux.Handle("POST /admin/oversight/payer-grants", padmin(grantH.GrantPayer))
	mux.Handle("DELETE /admin/oversight/payer-grants", padmin(grantH.RevokePayer))
	// Syslog source provisioning (padmin; auditMut in the chain records each mutation).
	mux.Handle("POST /admin/syslog-sources", padmin(syslogAdminH.Create))
	mux.Handle("GET /admin/syslog-sources", padmin(syslogAdminH.List))
	mux.Handle("POST /admin/syslog-sources/{id}/enabled", padmin(syslogAdminH.SetEnabled))
	mux.Handle("DELETE /admin/syslog-sources/{id}", padmin(syslogAdminH.Delete))
	// White-label branding: PUBLIC read (rate-limited, no auth — the login page needs it), padmin write.
	mux.Handle("GET /branding", httpx.Chain(http.HandlerFunc(brandingH.Get), apiLimit))
	mux.Handle("PUT /admin/branding", padmin(brandingH.Set))
	mux.Handle("GET /admin/tenants", padmin(tenantH.List))
	mux.Handle("GET /admin/tenants/{id}", padmin(tenantH.Get))
	// Tenant governance (§6.1). Status lifecycle is a provider action (platform_admin only);
	// profile/escalation/authority/history are the customer's own config (platform_admin or
	// the tenant's own customer_admin — self-scope enforced in the handler).
	mux.Handle("POST /admin/tenants/{id}/status", padmin(tenantH.SetStatus))
	mux.Handle("GET /admin/tenants/{id}/profile", ssoAdmin(tenantH.GetProfile))
	mux.Handle("PUT /admin/tenants/{id}/profile", ssoAdmin(tenantH.UpdateProfile))
	mux.Handle("GET /admin/tenants/{id}/escalation-contacts", ssoAdmin(tenantH.ListEscalation))
	mux.Handle("POST /admin/tenants/{id}/escalation-contacts", ssoAdmin(tenantH.AddEscalation))
	mux.Handle("DELETE /admin/tenants/{id}/escalation-contacts/{cid}", ssoAdmin(tenantH.DeleteEscalation))
	mux.Handle("GET /admin/tenants/{id}/authority-policies", ssoAdmin(tenantH.ListAuthority))
	mux.Handle("PUT /admin/tenants/{id}/authority-policies", ssoAdmin(tenantH.SetAuthority))
	mux.Handle("GET /admin/tenants/{id}/sla-policies", ssoAdmin(tenantH.ListSLA))
	mux.Handle("PUT /admin/tenants/{id}/sla-policies", ssoAdmin(tenantH.SetSLA))
	mux.Handle("GET /admin/tenants/{id}/correlation-policy", ssoAdmin(tenantH.GetCorrelation))
	mux.Handle("PUT /admin/tenants/{id}/correlation-policy", ssoAdmin(tenantH.SetCorrelation))
	mux.Handle("GET /admin/tenants/{id}/history", ssoAdmin(tenantH.ListHistory))
	mux.Handle("GET /admin/audit", ssoAdmin(auditH.List)) // immutable audit-trail search (Bucket-2, GOV-001/ADMIN-004)
	// Service accounts + API keys (§6.2 IAM-001/005/008). Programmatic principals for
	// connectors/customer scripts; the raw key is shown once at creation.
	mux.Handle("POST /admin/tenants/{id}/service-accounts", ssoAdmin(iamH.CreateServiceAccount))
	// G1 admin-issued password reset (platform_admin any tenant / customer_admin own; RP-1 role-domain guard in svc).
	mux.Handle("POST /admin/tenants/{id}/users/{uid}/reset-password", ssoAdmin(iamH.IssuePasswordReset))
	mux.Handle("POST /admin/tenants/{id}/users/{uid}/disable", ssoAdmin(iamH.DisableUser))       // L9 kill-switch
	mux.Handle("POST /admin/tenants/{id}/users/{uid}/reactivate", ssoAdmin(iamH.ReactivateUser)) // L9
	mux.Handle("GET /admin/tenants/{id}/service-accounts", ssoAdmin(iamH.ListServiceAccounts))
	mux.Handle("POST /admin/tenants/{id}/service-accounts/{sid}/keys", ssoAdmin(iamH.CreateAPIKey))
	mux.Handle("GET /admin/tenants/{id}/service-accounts/{sid}/keys", ssoAdmin(iamH.ListAPIKeys))
	mux.Handle("DELETE /admin/tenants/{id}/api-keys/{kid}", ssoAdmin(iamH.RevokeAPIKey))
	// Session & access policy (§6.2 IAM-007): configurable TTL + IP allow-list + anomaly log.
	mux.Handle("GET /admin/tenants/{id}/session-policy", ssoAdmin(iamH.GetSessionPolicy))
	mux.Handle("PUT /admin/tenants/{id}/session-policy", ssoAdmin(iamH.UpdateSessionPolicy))
	// Invitations + access review (§6.2 IAM-001/008/009).
	mux.Handle("POST /admin/tenants/{id}/invitations", ssoAdmin(iamH.CreateInvitation))
	mux.Handle("GET /admin/tenants/{id}/invitations", ssoAdmin(iamH.ListInvitations))
	mux.Handle("DELETE /admin/tenants/{id}/invitations/{iid}", ssoAdmin(iamH.RevokeInvitation))
	mux.Handle("GET /admin/tenants/{id}/access-review", ssoAdmin(iamH.AccessReview))
	mux.Handle("POST /admin/users", padmin(iamH.Create))
	// ingestion (any authenticated principal for the scaffold)
	mux.Handle("POST /ingest", authed(ingestH.Ingest))
	mux.Handle("GET /events", provider(ingestH.Events))
	// alerts (SOC)
	// correlation (§6.7): risk-ranked clusters of related alerts
	mux.Handle("GET /correlations", provider(correlationH.List))
	mux.Handle("GET /correlations/{id}", provider(correlationH.Get))
	mux.Handle("GET /correlations/storm", provider(correlationH.Storm))            // COR-008 storm status (literal beats {id})
	mux.Handle("GET /correlations/metrics", provider(correlationH.Metrics))        // COR-010 over-correlation metric
	mux.Handle("GET /correlations/{id}/explain", provider(correlationH.Explain))   // COR-006 risk breakdown
	mux.Handle("PUT /correlations/{id}/override", provider(correlationH.Override)) // COR-009 analyst override
	// COR-007 suppression / maintenance windows: create/delete withholds auto-promotion → senior.
	mux.Handle("GET /correlation-suppressions", provider(correlationH.ListSuppressions))
	mux.Handle("POST /correlation-suppressions", senior(correlationH.CreateSuppression))
	mux.Handle("DELETE /correlation-suppressions/{id}", senior(correlationH.DeleteSuppression))
	mux.Handle("GET /alerts", provider(alertH.List))
	// Fleet console: cross-tenant alert queue for operator/SOC staff (provider-gated; resolver fail-closes for
	// any non-provider). Distinct from GET /alerts, which is the caller's own single tenant.
	mux.Handle("GET /fleet/alerts", provider(fleetH.Alerts))
	// Fleet writes: target tenant resolved from the alert + scope-checked; mutation + audit land in the target.
	mux.Handle("POST /fleet/alerts/{id}/assign", provider(fleetH.AssignAlert))
	mux.Handle("POST /fleet/alerts/{id}/disposition", provider(fleetH.DispositionAlert))
	// Fleet DESTRUCTIVE (seam #3): fire/approve a SOAR containment on a target tenant's alert. Per-target
	// authority is evaluated in the target's context; effect + audit land durably in the target (supervisor).
	// L7: the cross-tenant containment FIRE is gated to `senior` (analyst_t2+), matching the same-tenant
	// POST /playbooks/{id}/run — a higher-consequence route must not have a lower role bar than the lesser
	// one. Approve/reject floors are additionally enforced in-service (soc_manager).
	mux.Handle("POST /fleet/alerts/{id}/contain", senior(fleetH.FireContainment))
	// M-1: cross-tenant containment approve/reject must not be reachable by analyst_t1. Approve carries the
	// execution authority (matches same-tenant /soar/runs/{id}/approve = soarApprover); reject (cancel) is
	// gated to senior so a T1 can't cancel a senior's containment.
	mux.Handle("POST /fleet/alerts/{id}/contain/{runID}/approve", soarApprover(fleetH.ApproveContainment))
	mux.Handle("POST /fleet/alerts/{id}/contain/{runID}/reject", senior(fleetH.RejectContainment))
	mux.Handle("GET /alerts/{id}", provider(alertH.Get))
	mux.Handle("POST /alerts/{id}/assign", provider(alertH.Assign))
	mux.Handle("POST /alerts/{id}/disposition", provider(alertH.Disposition)) // DET-007 FP feedback
	mux.Handle("POST /alerts/{id}/promote", senior(incidentH.PromoteFromAlert))
	mux.Handle("POST /alerts/{id}/summarise", aiProvider(aiH.SummariseAlert))
	mux.Handle("POST /incidents/{id}/triage", aiProvider(aiH.TriageIncident))
	// §6.12 #117 AI-provider config. Platform-admin: global default + allowlist + per-tenant policy. Tenant-admin:
	// own override (kind must be within policy; base_url must be allowlisted — enforced at save in ConfigService).
	mux.Handle("GET /admin/ai/provider", padmin(aiCfgH.GetGlobalProvider))
	mux.Handle("PUT /admin/ai/provider", padmin(aiCfgH.SetGlobalProvider))
	mux.Handle("GET /admin/ai/allowed-endpoints", padmin(aiCfgH.ListAllowedEndpoints))
	mux.Handle("POST /admin/ai/allowed-endpoints", padmin(aiCfgH.AddAllowedEndpoint))
	mux.Handle("DELETE /admin/ai/allowed-endpoints/{id}", padmin(aiCfgH.DeleteAllowedEndpoint))
	mux.Handle("PUT /admin/tenants/{id}/ai-policy", padmin(aiCfgH.SetTenantPolicy))
	mux.Handle("GET /tenant/ai/provider", ssoAdmin(aiCfgH.GetTenantProvider))
	mux.Handle("PUT /tenant/ai/provider", ssoAdmin(aiCfgH.SetTenantProvider))
	// §6.12 #188 AI-egress redaction — tenant-admin manages the mask-by-default policy + config-extensible patterns.
	// §6.12 AI governance — prompt registry + eval harness (padmin) + output feedback (analyst).
	mux.Handle("GET /admin/ai/prompts", padmin(aiGovH.ListPrompts))
	mux.Handle("POST /admin/ai/prompts", padmin(aiGovH.CreatePrompt))
	mux.Handle("GET /admin/ai/prompts/{key}/versions", padmin(aiGovH.ListVersions))
	mux.Handle("POST /admin/ai/prompts/{key}/versions", padmin(aiGovH.AddVersion))
	mux.Handle("POST /admin/ai/prompts/{key}/versions/{version}/activate", padmin(aiGovH.ActivateVersion))
	mux.Handle("GET /admin/ai/eval/cases", padmin(aiGovH.ListCases))
	mux.Handle("POST /admin/ai/eval/runs", padmin(aiGovH.RunEval))
	mux.Handle("GET /admin/ai/eval/runs", padmin(aiGovH.ListRuns))
	mux.Handle("GET /admin/ai/eval/runs/{id}", padmin(aiGovH.GetRun))
	mux.Handle("POST /ai/outputs/{ref}/feedback", provider(aiGovH.SubmitFeedback))
	mux.Handle("GET /ai/outputs/{ref}/feedback", provider(aiGovH.ListFeedback))

	mux.Handle("GET /tenant/ai/redaction", ssoAdmin(redactionH.GetPolicy))
	mux.Handle("PUT /tenant/ai/redaction", ssoAdmin(redactionH.SetPolicy))
	mux.Handle("GET /tenant/ai/redaction/patterns", ssoAdmin(redactionH.ListPatterns))
	mux.Handle("POST /tenant/ai/redaction/patterns", ssoAdmin(redactionH.AddPattern))
	mux.Handle("DELETE /tenant/ai/redaction/patterns/{id}", ssoAdmin(redactionH.DeletePattern))
	// §6.9 #124 I-1 investigation hunt-query (INV-006 / API-INV-006 + API-INV-001). Provider-gated (analyst_t1+);
	// allow-listed predicates compile to bound-param SQL under the tenant's RLS context, every run read-audited.
	mux.Handle("POST /investigation/run-hunt-query", provider(investigationH.RunHunt))
	mux.Handle("PATCH /investigation/search-events", provider(investigationH.RunHunt))
	// §6.9 #124 I-3 typed entity profile + pivot (INV-003/004 / API-INV-002/003). Composes the tenant-scoped
	// entitygraph service; a pivot neighbor is derived from the tenant's own alerts, never a cross-tenant ref.
	mux.Handle("GET /investigation/get-entity-profile", provider(investigationH.EntityProfile))
	mux.Handle("GET /investigation/get-entity-graph", provider(investigationH.EntityGraph))
	// §6.9 #124 I-4 structured forensic timeline (INV-002 / API-INV-004) + I-5 data-gap panel (INV-009).
	mux.Handle("GET /investigation/get-timeline", provider(investigationH.GetTimeline))
	// #188 raw-event fetch — the untransformed payload is the most sensitive read; senior-gated, RLS-confined,
	// fail-closed-audited (kind=raw_event) per access.
	mux.Handle("GET /investigation/raw-event/{id}", senior(investigationH.GetRawEvent))
	mux.Handle("GET /investigation/case-timeline", provider(investigationH.CaseTimeline)) // #188 multi-lane case timeline
	mux.Handle("GET /investigation/data-gaps", provider(investigationH.DataGaps))
	// §6.18 #122 platform-admin surface. Feature-flag set/rollback runs the safety gate (immutable rejected; protected
	// weakening needs senior+four-eyes+reason+HIGH-alert+time-box). Tenant lifecycle: legal-hold set is routine, CLEAR
	// needs the elevated envelope (M-3); offboard runs the uniform purge (blocked while on hold) + cert of destruction.
	mux.Handle("GET /admin/flags", padmin(padminH.ListFlags))
	mux.Handle("PUT /admin/flags", padmin(padminH.SetFlag))
	mux.Handle("POST /admin/flags/rollback", padmin(padminH.RollbackFlag))
	mux.Handle("POST /admin/tenants/{id}/legal-hold", padmin(padminH.SetLegalHold))
	mux.Handle("DELETE /admin/tenants/{id}/legal-hold", padmin(padminH.ClearLegalHold))
	mux.Handle("POST /admin/tenants/{id}/mark-exported", padmin(padminH.MarkExported))
	mux.Handle("POST /admin/tenants/{id}/offboard", padmin(padminH.OffboardTenant))
	mux.Handle("POST /admin/maintenance-windows", padmin(padminH.CreateWindow))
	// detection engineering
	mux.Handle("GET /detections", provider(detectionH.List))
	mux.Handle("POST /detections", detEng(detectionH.Create))
	mux.Handle("POST /detections/import/sigma", detEng(detectionH.ImportSigma))
	mux.Handle("POST /detections/cel", detEng(detectionH.CreateCEL))
	mux.Handle("POST /detections/{id}/enabled", detEng(detectionH.SetEnabled))
	// §6.6 detection-as-code lifecycle (DET-001/006/010 §9.4): promotion, metadata, versions, rollback.
	mux.Handle("POST /detections/{id}/transition", detEng(detectionH.Transition))
	mux.Handle("PUT /detections/{id}/metadata", detEng(detectionH.SetMetadata))
	mux.Handle("GET /detections/{id}/versions", provider(detectionH.Versions))
	mux.Handle("POST /detections/{id}/rollback", detEng(detectionH.Rollback))
	// §6.6 slice C: test-against-sample (DET-005), FP-feedback tuning (DET-007), coverage (DET-009), settings.
	mux.Handle("POST /detections/{id}/tests", detEng(detectionH.AddTestCase))
	mux.Handle("GET /detections/{id}/tests", provider(detectionH.ListTestCases))
	mux.Handle("POST /detections/{id}/tests/run", provider(detectionH.RunTests))
	mux.Handle("POST /detections/{id}/tests/samples", provider(detectionH.RunSamples))
	mux.Handle("DELETE /detections/{id}/tests/{tid}", detEng(detectionH.DeleteTestCase))
	mux.Handle("GET /detections/{id}/feedback", provider(detectionH.FeedbackStats))
	mux.Handle("GET /detections/tuning", provider(detectionH.Tuning))
	mux.Handle("GET /detections/coverage", provider(detectionH.Coverage))
	mux.Handle("GET /detections/settings", provider(detectionH.GetSettings))
	mux.Handle("PUT /detections/settings", detEng(detectionH.SetSettings))
	// connectors
	mux.Handle("GET /connectors/catalogue", provider(connectorH.Catalogue))
	mux.Handle("GET /connectors", provider(connectorH.List))
	mux.Handle("POST /connectors", senior(connectorH.Create))
	mux.Handle("PUT /connectors/{id}", senior(connectorH.Update)) // edit + enable/disable toggle
	mux.Handle("POST /connectors/{id}/test", senior(connectorH.TestConnection))
	mux.Handle("PUT /connectors/{id}/cred-expiry", senior(connectorH.SetCredExpiry)) // #188 record credential expiry
	mux.Handle("DELETE /connectors/{id}", senior(connectorH.Delete))
	// public webhook ingestion (source-key authenticated, per-IP rate limited)
	webhookLimit := ratelimit.Middleware(ratelimit.Build(redisClient, 50, 100, "webhook"), ratelimit.ByIP)
	mux.Handle("POST /ingest/webhook/{id}", httpx.Chain(http.HandlerFunc(connectorH.Webhook), webhookLimit))
	// SOAR (playbooks, runs, approvals, authority-to-act)
	mux.Handle("GET /playbooks", provider(soarH.ListPlaybooks))
	mux.Handle("POST /playbooks/{id}/run", senior(soarH.Run))
	// Playbook authoring (#187 slice A) — tenant-owned only, soc_manager+.
	mux.Handle("POST /soar/playbooks", soarAuthor(soarH.CreatePlaybook))
	mux.Handle("PUT /soar/playbooks/{id}", soarAuthor(soarH.UpdatePlaybook))
	mux.Handle("PATCH /soar/playbooks/{id}/enabled", soarAuthor(soarH.SetPlaybookEnabled))
	mux.Handle("GET /soar/action-records", provider(soarH.ListActionRecords)) // #187 slice C: internal-action records
	mux.Handle("GET /soar/runs", provider(soarH.ListRuns))
	mux.Handle("GET /soar/runs/{id}", provider(soarH.GetRun))
	mux.Handle("POST /soar/runs/{id}/approve", soarApprover(soarH.Approve))
	mux.Handle("POST /soar/runs/{id}/reject", soarApprover(soarH.Reject))
	// #188 customer-approval: issue a single-use link for a pending run (internal, soarApprover); the public
	// approve-link endpoint consumes it (the token is the capability — no session); tenant authority routing.
	mux.Handle("POST /soar/runs/{id}/approval-link", soarApprover(soarH.IssueApprovalLink))
	mux.Handle("POST /soar/approve-link", httpx.Chain(http.HandlerFunc(soarH.ApproveViaLink), loginLimit))
	mux.Handle("GET /soar/customer-approval", provider(soarH.GetCustomerApprovalPolicy))
	mux.Handle("PUT /soar/customer-approval", soarApprover(soarH.SetCustomerApprovalPolicy))
	// §6.14 #188 retention: view policy + sweep log (provider); enabling live deletion is a tenant-admin action.
	mux.Handle("GET /retention", provider(retentionH.GetPolicy))
	mux.Handle("PUT /retention", ssoAdmin(retentionH.SetPolicy))
	mux.Handle("GET /retention/sweeps", provider(retentionH.ListSweeps))
	mux.Handle("POST /soar/runs/{id}/reverse", soarApprover(soarH.Reverse)) // §6.11 slice B: undo containment (MUST-3)
	mux.Handle("POST /soar/authority", padmin(soarH.SetAuthority))
	mux.Handle("GET /soar/action-catalog", provider(soarH.ListActionCatalog))
	mux.Handle("PUT /soar/action-catalog", padmin(soarH.SetActionCatalog))
	// §6.11 slice B: destructive-action safety config (read provider; write platform-admin — enabling
	// real containment for a tenant and the global kill-switch are the highest-consequence toggles).
	mux.Handle("GET /soar/settings", provider(soarH.GetSettings))
	mux.Handle("PUT /soar/settings", padmin(soarH.SetSettings))
	mux.Handle("GET /soar/platform", padmin(soarH.GetPlatform))
	mux.Handle("PUT /soar/platform", padmin(soarH.SetPlatform))
	// threat intelligence (watchlist)
	mux.Handle("GET /threat-intel", provider(threatH.List))
	mux.Handle("POST /threat-intel", senior(threatH.Add))
	// STIX 2.1 object store (§6.10 TI-001..004). Reads are provider-wide; writes (manual add /
	// bundle import) are senior — same gate as watchlist writes.
	mux.Handle("GET /threat-intel/stix", provider(threatH.ListStix))
	mux.Handle("GET /threat-intel/stix/{id}", provider(threatH.GetStix))
	mux.Handle("POST /threat-intel/stix", senior(threatH.AddStix))
	mux.Handle("POST /threat-intel/stix/bundle", senior(threatH.ImportBundle))
	// §6.10 slice B: per-tenant decay/sighting tuning (read provider-wide, write senior).
	mux.Handle("GET /threat-intel/settings", provider(threatH.GetSettings))
	mux.Handle("PUT /threat-intel/settings", senior(threatH.SetSettings))
	// §6.5 slice A: normalization data-quality dashboard + drift (read provider, write senior).
	mux.Handle("GET /normalization/quality", provider(normH.Quality))
	mux.Handle("GET /normalization/settings", provider(normH.GetSettings))
	mux.Handle("PUT /normalization/settings", senior(normH.SetSettings))
	// reporting
	mux.Handle("GET /reports/summary", provider(reportingH.SummaryHTTP))
	// §6.13 #125 report export (REP-007 JSON/CSV/XLSX). Generate under tenant scope + caps; download is a
	// session-authorized GET (RLS-confined), response hardened; every generate/download audited (REP-008).
	mux.Handle("POST /reports", provider(reportExportH.Create))
	// #188 regulatory breach-notification report — a compliance-sensitive per-incident artifact, gated at manager.
	mux.Handle("POST /reports/breach", manager(reportExportH.Breach))
	mux.Handle("GET /reports/{id}", provider(reportExportH.Get))
	mux.Handle("GET /reports/{id}/download", provider(reportExportH.Download))
	// compliance (§6.14): config-driven frameworks + real per-tenant assessment; manual override is senior.
	mux.Handle("GET /compliance/frameworks", provider(complianceH.Frameworks))
	mux.Handle("GET /compliance/controls", provider(complianceH.Controls))
	mux.Handle("GET /compliance/coverage", provider(complianceH.Coverage))
	mux.Handle("PUT /compliance/status", manager(complianceH.SetStatus)) // R5-M4: auditor-facing attestation is manager-gated
	// billing / entitlements
	mux.Handle("GET /billing/entitlements", provider(billingH.Get))
	mux.Handle("PUT /billing/entitlements", padmin(billingH.Set))
	// §6.17 #126 billing. Pricing WRITES are padmin-only (a tenant has no path to price). Usage/invoice READS are
	// tenant-scoped + manager-gated (finance/admin tier, not every analyst). Metering has NO write endpoint —
	// usage is server-derived only.
	mux.Handle("GET /admin/billing/packages", padmin(billingH.ListPackages))
	mux.Handle("POST /admin/billing/packages", padmin(billingH.CreatePackage))
	mux.Handle("POST /admin/billing/packages/{id}/rates", padmin(billingH.SetRate))
	mux.Handle("PUT /admin/tenants/{id}/billing-package", padmin(billingH.AssignPackage))
	mux.Handle("GET /billing/usage", manager(billingH.Usage))
	mux.Handle("GET /billing/invoice", manager(billingH.Invoice))
	// §6.17 slice B: umbrella accounts + billing modes + suspension. Account/mode/suspension writes are padmin-only
	// (a tenant can't self-mark covered/comp or re-parent). Account-level suspend requires senior + raises a HIGH
	// alert (service-enforced). The account rollup reads only the account's own covered tenants.
	mux.Handle("GET /admin/billing/accounts", padmin(billingH.ListAccounts))
	mux.Handle("POST /admin/billing/accounts", padmin(billingH.CreateAccount))
	mux.Handle("PUT /admin/tenants/{id}/billing-mode", padmin(billingH.SetMode))
	mux.Handle("POST /admin/tenants/{id}/billing-suspend", padmin(billingH.SuspendTenant))
	mux.Handle("POST /admin/billing/accounts/{id}/suspend", padmin(billingH.SuspendAccount))
	// padmin (not manager): the umbrella-account invoice is a cross-tenant aggregate; a provider soc_manager must
	// not read an arbitrary account's spend by id (BOLA). Matches the account WRITES, which are all padmin-only.
	mux.Handle("GET /admin/billing/accounts/{id}/invoice", padmin(billingH.AccountInvoice))
	// notifications
	mux.Handle("POST /notify/test", senior(notifyH.Test))
	// §6.16 per-tenant email/SMS sender config (COMM-001); secrets vault-encrypted, manager-gated.
	mux.Handle("GET /notify/senders", provider(notifyH.ListSenders))
	mux.Handle("PUT /notify/senders", manager(notifyH.ConfigureSender))
	// §6.16 slice C: templates (COMM-007), settings/throttle+locale (COMM-006/008), secure links (COMM-009).
	mux.Handle("GET /notify/templates", provider(notifyH.ListTemplates))
	mux.Handle("PUT /notify/templates", manager(notifyH.UpsertTemplate))
	mux.Handle("PUT /notify/settings", manager(notifyH.UpdateSettings))
	mux.Handle("POST /notify/links", provider(notifyH.MintLink))
	mux.Handle("GET /notify/links/verify", provider(notifyH.VerifyLink))
	// Per-user in-app inbox (§6.16): any authenticated user, scoped to their OWN notifications.
	mux.Handle("GET /notify/inbox", authed(inboxH.List))
	mux.Handle("GET /notify/inbox/unread-count", authed(inboxH.UnreadCount))
	mux.Handle("POST /notify/inbox/read-all", authed(inboxH.MarkAllRead))
	mux.Handle("POST /notify/inbox/{id}/read", authed(inboxH.MarkRead))
	mux.Handle("GET /notify/inbox/prefs", authed(inboxH.GetPrefs))
	mux.Handle("PUT /notify/inbox/prefs", authed(inboxH.SetPrefs))
	// incidents (SOC)
	mux.Handle("GET /incidents", provider(incidentH.List))
	mux.Handle("GET /incidents/at-risk", provider(incidentH.AtRisk)) // literal beats {id}
	mux.Handle("GET /incidents/{id}", provider(incidentH.Get))
	mux.Handle("GET /incidents/{id}/alerts", provider(alertH.ByIncident)) // linked-alerts panel (Bucket-2)
	mux.Handle("GET /incidents/{id}/evidence-pack", senior(evidenceH.Pack))
	mux.Handle("GET /evidence/public-key", provider(evidenceH.PublicKey)) // publish for out-of-band verification
	// Asset inventory (§6.15)
	mux.Handle("POST /assets", manager(assetH.Create))
	mux.Handle("POST /assets/bulk", manager(assetH.BulkCreate)) // #188 bulk import
	mux.Handle("GET /assets", provider(assetH.List))
	mux.Handle("GET /assets/{id}", provider(assetH.Get))
	// Vulnerability & exposure (§6.15). Writes drive exposure/priority → manager-gated.
	mux.Handle("POST /vulnerabilities", manager(vulnH.Create))
	mux.Handle("POST /vulnerabilities/bulk", manager(vulnH.BulkCreate)) // #188 bulk import
	mux.Handle("GET /vulnerabilities", provider(vulnH.List))
	mux.Handle("GET /vulnerabilities/{id}", provider(vulnH.Get))
	mux.Handle("GET /exposure/summary", provider(vulnH.Exposure))
	// Entity graph (§6.9)
	mux.Handle("GET /entities/graph", provider(entityGraphH.Graph))
	mux.Handle("GET /incidents/{id}/customer-timeline", provider(incidentH.CustomerTimeline))
	mux.Handle("POST /incidents/{id}/assign", provider(incidentH.Assign))
	mux.Handle("POST /incidents/{id}/notes", provider(incidentH.AddNote))
	mux.Handle("POST /incidents/{id}/transition", provider(incidentH.Transition))
	// §6.8 slice B: tasks (CASE-005), categories (CASE-007), parent/child + major (CASE-006).
	mux.Handle("GET /incident-categories", provider(incidentH.ListCategories))
	mux.Handle("GET /incidents/{id}/tasks", provider(incidentH.ListTasks))
	mux.Handle("POST /incidents/{id}/tasks", provider(incidentH.CreateTask))
	mux.Handle("PUT /incident-tasks/{id}", provider(incidentH.UpdateTask))
	mux.Handle("PUT /incidents/{id}/category", provider(incidentH.SetCategory))
	mux.Handle("GET /incidents/{id}/children", provider(incidentH.Children))
	mux.Handle("POST /incidents/{id}/parent", provider(incidentH.LinkParent))
	mux.Handle("PUT /incidents/{id}/major", senior(incidentH.SetMajor)) // declaring a major incident is significant
	// §6.8 slice C: attachments/chain-of-custody (CASE-008), knowledge-base links (CASE-010).
	mux.Handle("GET /incidents/{id}/attachments", provider(incidentH.ListAttachments))
	mux.Handle("POST /incidents/{id}/attachments", provider(incidentH.AddAttachment))
	mux.Handle("GET /incidents/{id}/kb-links", provider(incidentH.ListKBLinks))
	mux.Handle("POST /incidents/{id}/kb-links", provider(incidentH.LinkKB))
	mux.Handle("GET /knowledge-base", provider(incidentH.ListKB))
	mux.Handle("POST /knowledge-base", provider(incidentH.CreateKB))
	mux.Handle("POST /incidents/{id}/close", senior(incidentH.Close))

	// --- Customer read-side (Slice A): audience-projected reads. THE ONLY handlers on customerRead/oversight
	// read chains are custReadH.* (fenced by scripts/check-audience-projection.sh). Customer sees redacted
	// projections of their own tenant; regulator sees grant-scoped metadata-only aggregates. ---
	mux.Handle("GET /customer/incidents", customerRead(custReadH.ListIncidents))
	mux.Handle("GET /customer/incidents/{id}", customerRead(custReadH.GetIncident))
	mux.Handle("GET /customer/alerts", customerRead(custReadH.ListAlerts))
	mux.Handle("GET /oversight/incidents-rollup", oversight(custReadH.IncidentRollup))
	mux.Handle("GET /oversight/alerts-rollup", oversight(custReadH.AlertRollup))
	// Provider-operator configures what each customer tenant sees (a customer cannot self-widen).
	mux.Handle("GET /admin/tenants/{tenant_id}/disclosure-policy", padmin(custReadH.GetDisclosurePolicy))
	mux.Handle("PUT /admin/tenants/{tenant_id}/disclosure-policy", padmin(custReadH.SetDisclosurePolicy))

	// auth.CSRF() enforces the double-submit token on unsafe methods of COOKIE-authenticated requests (ADR-0007);
	// it self-skips Bearer/API-key/pre-login requests, so it's safe as a global middleware. Placed after CORS so
	// preflight OPTIONS is answered first.
	handler := httpx.Chain(mux, httpx.RequestID, httpx.Recover(log), httpx.CORS(cfg.CORSOrigin), auth.CSRF(), tracing.Middleware(), metrics.Middleware(), httpx.AccessLog(log))

	// --- inline ingest worker (dev convenience; prod runs cmd/worker) ---
	workerCtx, stopWorker := context.WithCancel(ctx)
	defer stopWorker()

	// Syslog listener (Ghana L connector): mTLS network ingress, config-gated OFF and bound to a PRIVATE
	// interface only. Dormant unless NIRVET_SYSLOG_BIND is set. Its own goroutine — a listener panic is
	// panic-guarded per connection and cannot take down the HTTP server.
	if cfg.SyslogBind != "" {
		if cert, cerr := tls.LoadX509KeyPair(cfg.SyslogTLSCert, cfg.SyslogTLSKey); cerr != nil {
			log.Error("syslog listener NOT started: TLS cert/key load failed", "err", cerr)
		} else {
			sl := syslogd.New(syslogd.NewSourceStore(db), ingestSvc, log, syslogd.Config{BindAddr: cfg.SyslogBind, ServerCert: cert})
			go func() {
				if err := sl.Serve(workerCtx); err != nil {
					log.Error("syslog listener stopped", "err", err)
				}
			}()
			log.Info("syslog listener started (mTLS)", "bind", cfg.SyslogBind)
		}
	}
	if cfg.InlineWorker {
		wk := ingestion.NewWorker(jobs, events, enricher, detEngine, alertSvc, log).WithCorrelator(correlationSvc).WithNormQuality(normQ)
		go wk.Start(workerCtx, time.Second)
		poller := connector.NewPoller(connector.NewRepository(db), vault, ingestSvc, log)
		go poller.Start(workerCtx, time.Minute)
		// Re-enqueue raw events orphaned between StoreRaw and Enqueue (SEC Critical #4).
		go ingestSvc.StartReconciler(workerCtx, log, 30*time.Second, 60*time.Second, 100)
		// DET-002 stateful-detection window reaper: purge expired (entity,window) state so it can't grow unbounded.
		go detEngine.StartWindowReaper(workerCtx, log)
		// Vendor posture projection (MA-4): periodically recompute each tenant's metadata-only posture from
		// incident metadata (slice-A population driver; on-transition triggering is a documented follow-on).
		go postureProjector.StartRefreshLoop(workerCtx, log, time.Minute)
		// SLA breach alerting (§6.8): claim + timeline + durably enqueue once per deadline.
		go incidentSvc.StartSLASweeper(workerCtx, log, time.Minute, 200)
		// #188 connector credential-expiry reminder: claim + durably enqueue once, before a credential lapses.
		go connSvc.StartCredExpiryReaper(workerCtx, log)
		// Notification dispatcher: drains the outbox and delivers with retry (§6.16, R3 §6.5).
		go notifySvc.StartDispatcher(workerCtx, log, 15*time.Second, 200)
		// Refresh-token reaper (ADR-0007 LOW #4): deletes un-redeemable refresh rows (expired / past absolute cap)
		// so the table doesn't grow unbounded. Hourly is ample — rows are already dead before deletion.
		go iamSvc.StartRefreshReaper(workerCtx, log, time.Hour)
		// #188 retention enforcement: per-tenant telemetry sweep (dry-run until a tenant enables; legal-hold skips).
		go retentionSvc.StartRetentionReaper(workerCtx, log, 6*time.Hour)
		log.Info("inline ingest worker + connector poller + reconciler + sla sweeper + notification dispatcher + refresh reaper started")
	}

	// M-4 (DoS): full server timeouts + a bounded header + a concurrent-connection cap, so a slow-loris /
	// header-flood / connection-exhaustion attack can't tie up the API. WriteTimeout is generous for large
	// report/evidence downloads. The syslog listener already limits connections the same way.
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      300 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	ln, lerr := net.Listen("tcp", cfg.HTTPAddr)
	if lerr != nil {
		log.Error("listen error", "err", lerr)
		os.Exit(1)
	}
	ln = netutil.LimitListener(ln, httpMaxConns)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// caseJournalAdapter adapts incident.Service to investigation.CaseJournalReader for the #188 multi-lane case
// timeline, mapping the incident journal into the investigation-owned shape so investigation stays decoupled.
type caseJournalAdapter struct{ inc *incident.Service }

func (a caseJournalAdapter) CaseJournal(ctx context.Context, tenantID, incidentID uuid.UUID) ([]investigation.CaseJournalEntry, error) {
	entries, err := a.inc.Timeline(ctx, tenantID, incidentID)
	if err != nil {
		return nil, err
	}
	out := make([]investigation.CaseJournalEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, investigation.CaseJournalEntry{At: e.At, Author: e.Author, Kind: e.Kind, Visibility: e.Visibility, Note: e.Note})
	}
	return out, nil
}

// approverActiveAdapter adapts iam.Service to soar.ApproverValidator (#188) — re-validates a recorded internal
// approver is still an active user at execution time.
type approverActiveAdapter struct{ iam *iam.Service }

func (a approverActiveAdapter) IsActive(ctx context.Context, tenantID, userID uuid.UUID) bool {
	return a.iam.ActiveInTenant(ctx, tenantID, userID)
}

// breachIncidentAdapter adapts incident.Service to reporting.BreachIncidentReader for the #188 regulatory breach
// report, projecting the incident (read tenant-scoped under RLS) into the reporting-owned shape so reporting stays
// free of an incident import.
type breachIncidentAdapter struct{ inc *incident.Service }

func (a breachIncidentAdapter) BreachIncident(ctx context.Context, tenantID, incidentID uuid.UUID) (reporting.BreachIncident, error) {
	i, err := a.inc.Get(ctx, tenantID, incidentID)
	if err != nil {
		return reporting.BreachIncident{}, err // not-found on foreign/absent id
	}
	return reporting.BreachIncident{
		ID:             i.ID,
		Title:          i.Title,
		Severity:       i.Severity,
		Category:       i.Category,
		Stage:          string(i.Stage),
		CreatedAt:      i.CreatedAt,
		AcknowledgedAt: i.AcknowledgedAt,
		ClosedAt:       i.ClosedAt,
		Disposition:    i.Disposition,
		RootCause:      i.RootCause,
		Impact:         i.Impact,
		ActionsTaken:   i.ActionsTaken,
		LessonsLearned: i.LessonsLearned,
		CustomerAck:    i.CustomerAck,
	}, nil
}
