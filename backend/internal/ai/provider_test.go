package ai

// §6.12 #117 A-2 — Provider seam unit tests. No DB, no behavior change to the service yet: prove the interface,
// the anthropic adapter, and the disabled fallback in isolation.

import (
	"context"
	"errors"
	"testing"
)

func TestDisabledProvider(t *testing.T) {
	p := newDisabledProvider()
	if p.Available() {
		t.Fatal("disabled provider must never be available (forces the deterministic fallback)")
	}
	if p.Model() != string(KindDisabled) {
		t.Fatalf("model label = %q, want %q", p.Model(), KindDisabled)
	}
	if _, err := p.Complete(context.Background(), "s", "u"); !errors.Is(err, ErrProviderDisabled) {
		t.Fatalf("disabled Complete must return ErrProviderDisabled, got %v", err)
	}
}

func TestAnthropicProviderNoKeyUnavailable(t *testing.T) {
	// The Anthropic provider IS the existing Gateway; with no key it is unavailable → the service falls back to
	// the deterministic evidence-only summary exactly as before this feature. This is the back-compat anchor.
	p := newAnthropicProvider("", "")
	if p.Available() {
		t.Fatal("no-key anthropic provider must be unavailable")
	}
	if p.Model() != "offline-fallback" {
		t.Fatalf("no-key model label = %q, want offline-fallback", p.Model())
	}
}

func TestAnthropicProviderWithKeyAvailable(t *testing.T) {
	p := newAnthropicProvider("sk-test", "claude-sonnet-5")
	if !p.Available() {
		t.Fatal("keyed anthropic provider must be available")
	}
	if p.Model() != "claude-sonnet-5" {
		t.Fatalf("model = %q", p.Model())
	}
}
