package ai

// §6.12 #117 A-3 — resolver integration tests (migrated Postgres + FORCE RLS). Headline probes from the gate:
// resolution order (tenant→global→disabled), restriction fail-closed (kind∉allowed_kinds→disabled), the ALLOWLIST
// crux (an allowlisted INTERNAL endpoint WORKS end-to-end — internal-is-allowed by design), a non-allowlisted
// endpoint refused, path-smuggling rejected, and FORCE-RLS cross-tenant isolation (a tenant can't see another's row).

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func aiDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func aiTenant(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "ai-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return tn.ID
}

func ptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func setProviderRow(t *testing.T, db *database.DB, tid uuid.UUID, kind ProviderKind, baseURL, model, keyRef string) {
	t.Helper()
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ai_provider (tenant_id, provider_kind, base_url, model, api_key_ref)
			VALUES ($1,$2,$3,$4,$5)`, tid, string(kind), ptr(baseURL), model, ptr(keyRef))
		return e
	}); err != nil {
		t.Fatalf("set provider row: %v", err)
	}
}

func addAllowed(t *testing.T, db *database.DB, tid uuid.UUID, scheme, host string, port int) {
	t.Helper()
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ai_provider_allowed_endpoint (scheme, host, port) VALUES ($1,$2,$3)
			ON CONFLICT DO NOTHING`, scheme, host, port)
		return e
	}); err != nil {
		t.Fatalf("add allowed endpoint: %v", err)
	}
}

func setPolicy(t *testing.T, db *database.DB, tid uuid.UUID, kinds []string) {
	t.Helper()
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO tenant_ai_policy (tenant_id, allowed_kinds) VALUES ($1,$2)
			ON CONFLICT (tenant_id) DO UPDATE SET allowed_kinds = EXCLUDED.allowed_kinds`, tid, kinds)
		return e
	}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
}

func testResolver(db *database.DB) *Resolver {
	// cfg key/model stand in for the platform default; the key resolver seals a ref deterministically (vault is A-5).
	return NewResolver(NewRepository(db), "cfg-key", "cfg-model",
		KeyResolverFunc(func(_ context.Context, _ uuid.UUID, ref string) (string, error) { return "unsealed:" + ref, nil }))
}

// Global anthropic seed → a fresh tenant with no override resolves to anthropic-from-config (back-compat anchor).
func TestResolve_GlobalAnthropicDefault(t *testing.T) {
	db := aiDB(t)
	tid := aiTenant(t, db)
	res := testResolver(db).Resolve(context.Background(), tid)
	if res.Fallback || res.Kind != KindAnthropic {
		t.Fatalf("want anthropic default, got kind=%s fallback=%v reason=%s", res.Kind, res.Fallback, res.Reason)
	}
	if _, ok := res.Provider.(*Gateway); !ok {
		t.Fatalf("expected *Gateway anthropic provider, got %T", res.Provider)
	}
	if res.Model != "cfg-model" {
		t.Fatalf("global row model '' should fall to cfg-model, got %q", res.Model)
	}
}

// Tenant override wins the global default.
func TestResolve_TenantOverrideWins(t *testing.T) {
	db := aiDB(t)
	tid := aiTenant(t, db)
	setProviderRow(t, db, tid, KindDisabled, "", "", "")
	res := testResolver(db).Resolve(context.Background(), tid)
	if res.Kind != KindDisabled || res.Fallback {
		t.Fatalf("tenant disabled override should win (not a fallback), got kind=%s fallback=%v", res.Kind, res.Fallback)
	}
	if res.Provider.Available() {
		t.Fatal("disabled provider must be unavailable")
	}
}

// THE CRUX: an allowlisted INTERNAL endpoint resolves and WORKS end-to-end (internal-is-allowed by design).
func TestResolve_AllowlistedInternalEndpointWorks(t *testing.T) {
	db := aiDB(t)
	tid := aiTenant(t, db)
	srv := httptest.NewServer(oaiHandler(t, "sovereign summary", nil))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	addAllowed(t, db, tid, "http", u.Hostname(), port) // 127.0.0.1:PORT — an internal address, allowlisted on purpose
	setProviderRow(t, db, tid, KindOpenAICompatible, srv.URL, "local", "")

	res := testResolver(db).Resolve(context.Background(), tid)
	if res.Fallback || res.Kind != KindOpenAICompatible {
		t.Fatalf("allowlisted internal endpoint must resolve openai_compatible, got kind=%s fallback=%v reason=%s", res.Kind, res.Fallback, res.Reason)
	}
	if _, ok := res.Provider.(*openAICompatibleProvider); !ok {
		t.Fatalf("expected *openAICompatibleProvider, got %T", res.Provider)
	}
	got, err := res.Provider.Complete(context.Background(), "sys", "usr")
	if err != nil || got != "sovereign summary" {
		t.Fatalf("resolved provider must reach the internal endpoint: got %q err=%v", got, err)
	}
}

// A non-allowlisted endpoint (e.g. cloud metadata) → disabled fallback, NOT reached.
func TestResolve_NonAllowlistedRefused(t *testing.T) {
	db := aiDB(t)
	tid := aiTenant(t, db)
	setProviderRow(t, db, tid, KindOpenAICompatible, "http://169.254.169.254", "m", "")
	res := testResolver(db).Resolve(context.Background(), tid)
	if !res.Fallback || res.Reason != "endpoint_not_allowlisted" || res.Kind != KindDisabled {
		t.Fatalf("non-allowlisted endpoint must fail closed, got kind=%s fallback=%v reason=%s", res.Kind, res.Fallback, res.Reason)
	}
}

// Path smuggling in base_url is rejected before any allowlist/egress decision.
func TestResolve_PathSmugglingRejected(t *testing.T) {
	db := aiDB(t)
	tid := aiTenant(t, db)
	addAllowed(t, db, tid, "https", "llm.internal", 0)
	setProviderRow(t, db, tid, KindOpenAICompatible, "https://llm.internal/../evil", "m", "")
	res := testResolver(db).Resolve(context.Background(), tid)
	if !res.Fallback || res.Reason != "bad_base_url" {
		t.Fatalf("path in base_url must be rejected, got fallback=%v reason=%s", res.Fallback, res.Reason)
	}
}

// Restriction fail-closed: a tenant policy that forbids anthropic → the global anthropic default is NOT used.
func TestResolve_KindRestrictedFailsClosed(t *testing.T) {
	db := aiDB(t)
	tid := aiTenant(t, db)
	setPolicy(t, db, tid, []string{string(KindOpenAICompatible), string(KindDisabled)}) // sovereign: anthropic forbidden
	res := testResolver(db).Resolve(context.Background(), tid)                          // no tenant row → global anthropic
	if !res.Fallback || res.Reason != "kind_restricted" || res.Kind != KindDisabled {
		t.Fatalf("restricted tenant must not be routed to the forbidden default, got kind=%s fallback=%v reason=%s", res.Kind, res.Fallback, res.Reason)
	}
}

// FORCE-RLS: tenant B must not see tenant A's provider row — B resolves the global default, not A's openai endpoint.
func TestResolve_CrossTenantIsolation(t *testing.T) {
	db := aiDB(t)
	a := aiTenant(t, db)
	b := aiTenant(t, db)
	addAllowed(t, db, a, "https", "a-llm.internal", 0)
	setProviderRow(t, db, a, KindOpenAICompatible, "https://a-llm.internal", "m", "")
	res := testResolver(db).Resolve(context.Background(), b)
	if res.Kind != KindAnthropic {
		t.Fatalf("tenant B must resolve its own/global default, not A's openai row; got kind=%s endpoint=%s", res.Kind, res.Endpoint)
	}
}
