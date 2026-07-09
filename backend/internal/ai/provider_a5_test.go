package ai

// §6.12 #117 A-5 — the key-unseal path + per-call audit metadata. The resolver unseals a sealed api_key_ref through
// the vault under the correct scope (tenant vs global), and the AI-call audit records the provider it used + any
// fail-closed reason (no silent downgrade). The full Service.SummariseAlert path is covered by the existing ai
// tests; here we prove the new seam mechanics directly.

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
)

func TestVaultKeyResolver_RoundTrip(t *testing.T) {
	box := fakeBox{}
	scope := uuid.New()
	ct, _ := box.Seal(scope, []byte("sk-secret"))
	ref := base64.StdEncoding.EncodeToString(ct)

	got, err := NewVaultKeyResolver(box).ResolveKey(context.Background(), scope, ref)
	if err != nil || got != "sk-secret" {
		t.Fatalf("round-trip = %q err=%v", got, err)
	}
	if _, err := NewVaultKeyResolver(box).ResolveKey(context.Background(), scope, "not-base64!!"); err == nil {
		t.Fatal("a non-base64 ref must error")
	}
}

// A tenant anthropic row with a sealed key → the resolver unseals it and the provider is available (key present).
func TestResolve_UnsealsSealedKey(t *testing.T) {
	db := aiDB(t)
	tid := aiTenant(t, db)
	ct, _ := fakeBox{}.Seal(tid, []byte("sk-x"))
	setProviderRow(t, db, tid, KindAnthropic, "", "m", base64.StdEncoding.EncodeToString(ct))

	res := NewResolver(NewRepository(db), "", "", NewVaultKeyResolver(fakeBox{})).Resolve(context.Background(), tid)
	if res.Kind != KindAnthropic || res.Fallback {
		t.Fatalf("want anthropic, got kind=%s fallback=%v reason=%s", res.Kind, res.Fallback, res.Reason)
	}
	if !res.Provider.Available() {
		t.Fatal("provider must be available — the sealed key should have unsealed to a non-empty key")
	}
}

// A bad (undecryptable) key ref → fail-closed to disabled with key_unseal_error, never a keyless call.
func TestResolve_BadKeyFailsClosed(t *testing.T) {
	db := aiDB(t)
	tid := aiTenant(t, db)
	setProviderRow(t, db, tid, KindAnthropic, "", "m", "not-base64!!")

	res := NewResolver(NewRepository(db), "", "", NewVaultKeyResolver(fakeBox{})).Resolve(context.Background(), tid)
	if !res.Fallback || res.Reason != "key_unseal_error" || res.Kind != KindDisabled {
		t.Fatalf("bad key must fail closed, got kind=%s fallback=%v reason=%s", res.Kind, res.Fallback, res.Reason)
	}
}

func TestWithProviderMeta(t *testing.T) {
	// openai fallback: endpoint + fallback reason recorded; never a secret.
	m := withProviderMeta(map[string]any{}, Resolution{Kind: KindDisabled, Fallback: true, Reason: "kind_restricted"})
	if m["provider_kind"] != string(KindDisabled) || m["provider_fallback_reason"] != "kind_restricted" {
		t.Fatalf("fallback meta wrong: %v", m)
	}
	m2 := withProviderMeta(map[string]any{}, Resolution{Kind: KindOpenAICompatible, Endpoint: "https://llm.internal"})
	if m2["provider_endpoint"] != "https://llm.internal" {
		t.Fatalf("endpoint meta missing: %v", m2)
	}
	if _, hasReason := m2["provider_fallback_reason"]; hasReason {
		t.Fatal("a non-fallback resolution must not record a fallback reason")
	}
}
