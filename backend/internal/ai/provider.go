package ai

// §6.12 #117 A-2 — the Provider seam. An admin-configurable LLM backend resolved per (tenant, call): anthropic
// (fixed host), openai_compatible (allowlisted endpoint — A-3), or disabled (no LLM → deterministic fallback).
// ASSISTIVE-ONLY by construction: a Provider can only Complete text; it can never take an action (containment stays
// in soar under approval). The allowlist that gates openai_compatible is a DATA-EGRESS / RESIDENCY control (§1903),
// not merely SSRF hardening — it is the set of hosts a tenant's data may be sent to.

import (
	"context"
	"errors"
)

// ProviderKind is the configured LLM backend kind. Source of truth for the ai_provider.provider_kind CHECK
// (schemacheck guard #3 keeps this in lockstep with the column).
type ProviderKind string

const (
	KindAnthropic        ProviderKind = "anthropic"
	KindOpenAICompatible ProviderKind = "openai_compatible"
	KindDisabled         ProviderKind = "disabled"
)

// AllowedScheme is a permitted allowlist endpoint scheme (source of truth for ai_provider_allowed_endpoint.scheme).
type AllowedScheme string

const (
	SchemeHTTP  AllowedScheme = "http"
	SchemeHTTPS AllowedScheme = "https"
)

// ErrProviderDisabled is returned by a disabled provider's Complete; callers gate on Available() and never reach it.
var ErrProviderDisabled = errors.New("ai: provider disabled")

// Provider is a resolved LLM backend for one call. The existing *Gateway (Anthropic) already satisfies it.
type Provider interface {
	Available() bool // false → caller uses the deterministic fallback summary
	Model() string   // audit label
	Complete(ctx context.Context, system, user string) (string, error)
}

// compile-time: the Anthropic gateway is a Provider.
var _ Provider = (*Gateway)(nil)

// newAnthropicProvider builds the Anthropic provider (fixed api.anthropic.com host, netsafe-exempt). Key/model come
// from the platform config (global default) or a tenant's vault ref (wired in A-3).
func newAnthropicProvider(apiKey, model string) Provider { return NewGateway(apiKey, model) }

// disabledProvider is the "AI off / kind=disabled / restricted-out" backend: never available, so callers fall back
// to the deterministic evidence-only summary. Complete is never reached (Available()==false gates it) but is safe.
type disabledProvider struct{}

func newDisabledProvider() Provider { return disabledProvider{} }

func (disabledProvider) Available() bool { return false }
func (disabledProvider) Model() string   { return string(KindDisabled) }
func (disabledProvider) Complete(context.Context, string, string) (string, error) {
	return "", ErrProviderDisabled
}
