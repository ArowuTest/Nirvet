package ai

// §6.12 #117 A-3 — the fail-closed provider resolver. For one (tenant, call): load the effective provider row
// (tenant override, else global default) and the tenant's allowed_kinds, then build the Provider. Every ambiguous
// or restricted path resolves to disabled (→ the deterministic fallback summary), NEVER to an unintended egress:
//   * no provider row / infra error / key-unseal error → disabled
//   * resolved kind ∉ tenant allowed_kinds (§1903 restriction) → disabled  (a tenant can never be silently routed
//     to a provider its policy forbids)
//   * openai_compatible base_url not on the platform allowlist → disabled
// The caller (service, A-5) audits every fallback via Resolution.Reason (silent-withhold is the worst SOC failure).

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// KeyResolver unseals a vault api_key_ref to a plaintext key. Wired to the real vault (with decrypt-audit) in A-5;
// nil ref means keyless/config-default and never calls this.
type KeyResolver interface {
	ResolveKey(ctx context.Context, ref string) (string, error)
}

// KeyResolverFunc adapts a plain func.
type KeyResolverFunc func(ctx context.Context, ref string) (string, error)

// ResolveKey implements KeyResolver.
func (f KeyResolverFunc) ResolveKey(ctx context.Context, ref string) (string, error) {
	return f(ctx, ref)
}

// Resolution is the outcome of resolving a tenant's provider: the Provider plus the facts the caller audits.
type Resolution struct {
	Provider Provider
	Kind     ProviderKind
	Endpoint string // openai_compatible origin, else ""
	Model    string
	Fallback bool   // fell back to disabled for a reason other than an explicit disabled config
	Reason   string // audit reason when Fallback (e.g. kind_restricted, endpoint_not_allowlisted)
}

// Resolver resolves a tenant's configured AI provider, fail-closed.
type Resolver struct {
	repo     *Repository
	cfgKey   string              // platform Anthropic key: used for the global anthropic row with NULL api_key_ref (back-compat)
	cfgModel string              // platform default model for the anthropic default
	keys     KeyResolver         // vault unseal for non-null api_key_ref
	newHTTP  func() *http.Client // openai client factory (nil → hardened default in newOpenAICompatibleProvider)
}

// NewResolver builds the resolver. keys may be nil if no provider row uses a vault ref (e.g. dev).
func NewResolver(repo *Repository, cfgKey, cfgModel string, keys KeyResolver) *Resolver {
	return &Resolver{repo: repo, cfgKey: cfgKey, cfgModel: cfgModel, keys: keys}
}

// WithHTTPFactory injects the openai_compatible client factory (tests). Prod leaves it nil (hardened default).
func (r *Resolver) WithHTTPFactory(f func() *http.Client) *Resolver { r.newHTTP = f; return r }

// Resolve returns a Provider for the tenant, never erroring — a failure is expressed as a disabled fallback so the
// caller always has a usable (assistive-only) provider.
func (r *Resolver) Resolve(ctx context.Context, tenantID uuid.UUID) Resolution {
	disabled := func(reason string) Resolution {
		return Resolution{Provider: newDisabledProvider(), Kind: KindDisabled, Fallback: true, Reason: reason}
	}

	row, allowed, err := r.repo.ProviderConfig(ctx, tenantID)
	if err != nil {
		return disabled("resolve_error") // fail CLOSED on infra error — no egress under uncertainty
	}
	if !row.HasRow {
		return disabled("no_provider_configured")
	}
	if !contains(allowed, string(row.Kind)) {
		return disabled("kind_restricted") // §1903: tenant policy forbids this kind
	}

	switch row.Kind {
	case KindDisabled:
		// Explicitly configured off — the intended state, not a fallback (no audit reason).
		return Resolution{Provider: newDisabledProvider(), Kind: KindDisabled, Model: string(KindDisabled)}

	case KindAnthropic:
		key := r.cfgKey
		if row.APIKeyRef != "" {
			k, kerr := r.unseal(ctx, row.APIKeyRef)
			if kerr != nil {
				return disabled("key_unseal_error")
			}
			key = k
		}
		model := r.cfgModel
		if row.Model != "" {
			model = row.Model
		}
		return Resolution{Provider: newAnthropicProvider(key, model), Kind: KindAnthropic, Model: model}

	case KindOpenAICompatible:
		origin, scheme, host, port, perr := normalizeEndpoint(row.BaseURL)
		if perr != nil {
			return disabled("bad_base_url")
		}
		ok, aerr := r.repo.IsAllowedEndpoint(ctx, tenantID, scheme, host, port)
		if aerr != nil {
			return disabled("allowlist_error")
		}
		if !ok {
			return disabled("endpoint_not_allowlisted") // the data-egress boundary — refuse a non-allowlisted host
		}
		key := ""
		if row.APIKeyRef != "" {
			k, kerr := r.unseal(ctx, row.APIKeyRef)
			if kerr != nil {
				return disabled("key_unseal_error")
			}
			key = k
		}
		var hc *http.Client
		if r.newHTTP != nil {
			hc = r.newHTTP()
		}
		return Resolution{
			Provider: newOpenAICompatibleProvider(origin, row.Model, key, hc),
			Kind:     KindOpenAICompatible, Endpoint: origin, Model: row.Model,
		}

	default:
		return disabled("unknown_kind")
	}
}

func (r *Resolver) unseal(ctx context.Context, ref string) (string, error) {
	if r.keys == nil {
		return "", fmt.Errorf("ai: no key resolver configured but api_key_ref set")
	}
	return r.keys.ResolveKey(ctx, ref)
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// normalizeEndpoint parses a base_url into a validated origin (scheme://host[:port], NO path/query/userinfo) and its
// components. Rebuilding the request target from these components — never the raw string — is what makes the
// allowlist a hard boundary: a smuggled path, credential, or redirect cannot move the target off the allowlisted host.
func normalizeEndpoint(raw string) (origin, scheme, host string, port int, err error) {
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil {
		return "", "", "", 0, e
	}
	scheme = strings.ToLower(u.Scheme)
	if scheme != string(SchemeHTTP) && scheme != string(SchemeHTTPS) {
		return "", "", "", 0, fmt.Errorf("ai: unsupported scheme %q", u.Scheme)
	}
	if u.User != nil {
		return "", "", "", 0, fmt.Errorf("ai: userinfo not allowed in base_url")
	}
	host = strings.ToLower(u.Hostname())
	if host == "" {
		return "", "", "", 0, fmt.Errorf("ai: empty host in base_url")
	}
	if u.Path != "" && u.Path != "/" {
		return "", "", "", 0, fmt.Errorf("ai: base_url must not contain a path")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", "", "", 0, fmt.Errorf("ai: base_url must not contain a query or fragment")
	}
	if ps := u.Port(); ps != "" {
		port, e = strconv.Atoi(ps)
		if e != nil || port < 1 || port > 65535 {
			return "", "", "", 0, fmt.Errorf("ai: invalid port %q", ps)
		}
	}
	origin = scheme + "://" + host
	if port != 0 {
		origin += ":" + strconv.Itoa(port)
	}
	return origin, scheme, host, port, nil
}
