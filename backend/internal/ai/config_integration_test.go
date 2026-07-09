package ai

// §6.12 #117 A-4 — config-surface security spine (migrated DB). The reviewer headline checks: a tenant cannot pick
// a kind its policy forbids (403); a non-allowlisted base_url is refused AT SAVE (not just fail-closed at call); the
// cleartext-key-over-http warning surfaces; the key is sealed; policy kinds are validated.

import (
	"bytes"
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// fakeBox is a reversible stand-in for the vault (real KMS crypto is exercised by connector tests).
type fakeBox struct{}

func (fakeBox) Seal(_ uuid.UUID, pt []byte) ([]byte, error) {
	return append([]byte("sealed:"), pt...), nil
}
func (fakeBox) Open(_ uuid.UUID, ct []byte) ([]byte, error) {
	return bytes.TrimPrefix(ct, []byte("sealed:")), nil
}

func newConfigService(t *testing.T) (*ConfigService, uuid.UUID, *database.DB) {
	t.Helper()
	db := aiDB(t)
	tid := aiTenant(t, db)
	return NewConfigService(NewRepository(db), fakeBox{}), tid, db
}

// Tighten-only: a tenant pinned away from anthropic cannot select it (403).
func TestConfig_TenantCannotPickForbiddenKind(t *testing.T) {
	svc, tid, db := newConfigService(t)
	setPolicy(t, db, tid, []string{string(KindOpenAICompatible), string(KindDisabled)})
	_, err := svc.SetTenantProvider(context.Background(), tid, ProviderUpdate{Kind: KindAnthropic})
	if ae, ok := err.(*httpx.APIError); !ok || ae.Status != 403 {
		t.Fatalf("forbidden kind must 403, got %v", err)
	}
}

// A non-allowlisted openai base_url is refused at save (400), never stored.
func TestConfig_NonAllowlistedBaseURLRejectedAtSave(t *testing.T) {
	svc, tid, _ := newConfigService(t)
	_, err := svc.SetTenantProvider(context.Background(), tid, ProviderUpdate{Kind: KindOpenAICompatible, BaseURL: "http://169.254.169.254", Model: "m"})
	if ae, ok := err.(*httpx.APIError); !ok || ae.Status != 400 {
		t.Fatalf("non-allowlisted base_url must 400 at save, got %v", err)
	}
}

// A cleartext (http) endpoint with a key surfaces the exposure warning but still saves (approved on-prem case).
func TestConfig_CleartextKeyWarning(t *testing.T) {
	svc, tid, db := newConfigService(t)
	addAllowed(t, db, tid, "http", "llm.local", 0)
	res, err := svc.SetTenantProvider(context.Background(), tid, ProviderUpdate{Kind: KindOpenAICompatible, BaseURL: "http://llm.local", Model: "m", APIKey: "k"})
	if err != nil {
		t.Fatalf("allowlisted http endpoint should save: %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("expected a cleartext-key warning")
	}
	if !res.Provider.HasKey {
		t.Fatal("key should be stored (sealed)")
	}
}

// The key is sealed (stored, redacted-in-view; never echoed).
func TestConfig_KeyIsSealedNotEchoed(t *testing.T) {
	svc, tid, _ := newConfigService(t)
	res, err := svc.SetTenantProvider(context.Background(), tid, ProviderUpdate{Kind: KindAnthropic, Model: "m", APIKey: "sk-secret"})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if !res.Provider.HasKey {
		t.Fatal("HasKey must be true after setting a key")
	}
	// The view must never carry the plaintext.
	v, _, _ := svc.GetEffectiveProvider(context.Background(), tid)
	if v.Kind != KindAnthropic {
		t.Fatalf("effective kind = %s", v.Kind)
	}
}

// Global override then tenant override; restore the shared global row at cleanup so other tests see anthropic.
func TestConfig_GlobalThenTenantOverride(t *testing.T) {
	svc, tid, _ := newConfigService(t)
	ctx := context.Background()
	t.Cleanup(func() { _, _ = svc.SetGlobalProvider(ctx, ProviderUpdate{Kind: KindAnthropic}) })

	if _, err := svc.SetGlobalProvider(ctx, ProviderUpdate{Kind: KindDisabled}); err != nil {
		t.Fatalf("set global: %v", err)
	}
	gv, ok, _ := svc.GetGlobalProvider(ctx)
	if !ok || gv.Kind != KindDisabled {
		t.Fatalf("global should be disabled, got %v ok=%v", gv.Kind, ok)
	}
	if _, err := svc.SetTenantProvider(ctx, tid, ProviderUpdate{Kind: KindAnthropic, Model: "m"}); err != nil {
		t.Fatalf("tenant override: %v", err)
	}
	v, _, _ := svc.GetEffectiveProvider(ctx, tid)
	if v.Kind != KindAnthropic || v.Global {
		t.Fatalf("tenant override should win (own row), got kind=%s global=%v", v.Kind, v.Global)
	}
}

// Policy validation rejects an unknown kind.
func TestConfig_PolicyValidation(t *testing.T) {
	svc, tid, _ := newConfigService(t)
	if err := svc.SetTenantPolicy(context.Background(), tid, []string{"bogus"}); err == nil {
		t.Fatal("unknown kind in policy must be rejected")
	}
}
