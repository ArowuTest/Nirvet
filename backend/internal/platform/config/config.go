// Package config loads Nirvet platform configuration from environment variables.
// Twelve-factor style: everything is env-driven with sane local defaults.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config is the fully-resolved platform configuration.
type Config struct {
	Env         string // development | staging | production
	HTTPAddr    string // e.g. ":8080"
	DatabaseURL string // postgres DSN (runtime, non-owner RLS-bound role)

	// Auth
	JWTSecret  string
	JWTIssuer  string
	AccessTTL  time.Duration
	RefreshTTL time.Duration

	// CORS: allowed browser origin for the frontend (dev).
	CORSOrigin string

	// TrustedProxyDepth is the number of upstream proxies whose X-Forwarded-For
	// entries are trusted when deriving the client IP for rate limiting (1 = a single
	// platform load balancer). Prevents X-Forwarded-For spoofing of per-IP limits.
	TrustedProxyDepth int

	// Crypto / connector credential vault (ADR-0004)
	// SecretMasterKey is a base64 32-byte key used by the LOCAL AES-GCM cipher for dev.
	// In production this is replaced by GCP KMS (KMSKeyName), and the master key is unused.
	SecretMasterKey string
	KMSKeyName      string // GCP KMS CryptoKey resource name; empty => use local cipher

	// EvidenceSigningKey is a base64 32-byte Ed25519 seed used to sign exported evidence
	// packs (R2 H-B). Empty => an ephemeral per-process key (dev): packs are still really
	// signed, but cannot be verified across a restart. Required in production.
	EvidenceSigningKey string

	// Evidence/object storage (ADR-0002/0005). GCS bucket => cloud; else local dir.
	GCSBucket string
	BlobDir   string

	// Telemetry event store (ADR-0002). Empty => Postgres (MVP). Set a ClickHouse
	// DSN (clickhouse://user:pass@host:9000/db) to use the V1 columnar hot store.
	ClickHouseDSN string

	// AI copilot (SRS §6.12). Empty API key => offline deterministic fallback.
	AnthropicAPIKey string
	AIModel         string

	// Observability / tracing (NFR-007, ADR-0005). Empty endpoint => no-op tracer
	// (zero overhead, no network). Set to an OTLP/HTTP collector to export spans;
	// the endpoint is swappable local -> GCP Cloud Trace without code change.
	OTLPEndpoint string
	ServiceVer   string

	// Redis (scaling). Empty => in-memory rate limiting (per-instance). Set an
	// address (host:port) to make rate limits global across API replicas.
	RedisAddr string

	// Queue backend (ADR-0003). Empty => Postgres queue (MVP). Set a NATS URL
	// (nats://host:4222) to use the JetStream durable queue.
	NATSURL string

	// Ingestion (ADR-0003)
	IngestWorkers int
	InlineWorker  bool // run the ingest worker inside the api process (dev)

	// Bootstrap: first-run provider tenant + platform admin.
	BootstrapEmail    string
	BootstrapPassword string
}

// Load reads configuration from the environment, applying development defaults.
func Load() (*Config, error) {
	c := &Config{
		Env:                env("NIRVET_ENV", "development"),
		HTTPAddr:           env("NIRVET_HTTP_ADDR", ":8080"),
		DatabaseURL:        env("NIRVET_DATABASE_URL", "postgres://nirvet_app:nirvet_app@localhost:5432/nirvet?sslmode=disable"),
		JWTSecret:          env("NIRVET_JWT_SECRET", "dev-insecure-change-me"),
		JWTIssuer:          env("NIRVET_JWT_ISSUER", "nirvet"),
		CORSOrigin:         env("NIRVET_CORS_ORIGIN", "http://localhost:3000"),
		TrustedProxyDepth:  envInt("NIRVET_TRUSTED_PROXY_DEPTH", 1),
		AccessTTL:          envDuration("NIRVET_ACCESS_TTL", 15*time.Minute),
		RefreshTTL:         envDuration("NIRVET_REFRESH_TTL", 720*time.Hour),
		SecretMasterKey:    env("NIRVET_SECRET_MASTER_KEY", ""),
		KMSKeyName:         env("NIRVET_KMS_KEY_NAME", ""),
		EvidenceSigningKey: env("NIRVET_EVIDENCE_SIGNING_KEY", ""),
		AnthropicAPIKey:    env("NIRVET_ANTHROPIC_API_KEY", ""),
		AIModel:            env("NIRVET_AI_MODEL", "claude-sonnet-5"),
		GCSBucket:          env("NIRVET_GCS_BUCKET", ""),
		BlobDir:            env("NIRVET_BLOB_DIR", ""),
		ClickHouseDSN:      env("NIRVET_CLICKHOUSE_DSN", ""),
		OTLPEndpoint:       env("NIRVET_OTLP_ENDPOINT", env("OTEL_EXPORTER_OTLP_ENDPOINT", "")),
		ServiceVer:         env("NIRVET_SERVICE_VERSION", "dev"),
		RedisAddr:          env("NIRVET_REDIS_ADDR", ""),
		NATSURL:            env("NIRVET_NATS_URL", ""),
		IngestWorkers:      envInt("NIRVET_INGEST_WORKERS", 4),
		InlineWorker:       env("NIRVET_INLINE_WORKER", "true") == "true",
		BootstrapEmail:     env("NIRVET_BOOTSTRAP_EMAIL", "admin@nirvet.local"),
		BootstrapPassword:  env("NIRVET_BOOTSTRAP_PASSWORD", "ChangeMe123!"),
	}
	if c.IsProduction() && c.JWTSecret == "dev-insecure-change-me" {
		return nil, fmt.Errorf("config: NIRVET_JWT_SECRET must be set in production")
	}
	// Refuse to boot production on the default bootstrap credential — otherwise a
	// deployment ships with a publicly-known platform_admin password.
	if c.IsProduction() && c.BootstrapPassword == "ChangeMe123!" {
		return nil, fmt.Errorf("config: NIRVET_BOOTSTRAP_PASSWORD must be changed from the default in production")
	}
	// Vault (ADR-0004): the connector-credential + MFA-secret cipher must have
	// persistent key material in production. With neither KMS nor a master key set,
	// the local cipher falls back to an EPHEMERAL key — every stored secret becomes
	// unrecoverable across a restart — so refuse to boot. GCP KMS is the target
	// production backend; until it is implemented, a persistent NIRVET_SECRET_MASTER_KEY
	// is the supported path.
	if c.IsProduction() && c.KMSKeyName == "" && c.SecretMasterKey == "" {
		return nil, fmt.Errorf("config: set NIRVET_SECRET_MASTER_KEY (or NIRVET_KMS_KEY_NAME) in production; otherwise connector credentials and MFA secrets use an ephemeral key and are lost on restart")
	}
	// Evidence-pack signing key must be persistent in production, else exported packs
	// signed before a restart can no longer be verified (R2 H-B).
	if c.IsProduction() && c.EvidenceSigningKey == "" {
		return nil, fmt.Errorf("config: NIRVET_EVIDENCE_SIGNING_KEY (base64 32-byte Ed25519 seed) must be set in production so exported evidence packs are verifiable across restarts")
	}
	return c, nil
}

// IsProduction reports whether the platform is running in production mode.
func (c *Config) IsProduction() bool { return c.Env == "production" }

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
