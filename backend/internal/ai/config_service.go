package ai

// §6.12 #117 A-4 — the config-surface service: validation, key sealing, tighten-only enforcement. The auditMut
// middleware records every mutation, so this layer does NOT write change-audit rows itself (the per-CALL
// decrypt-audit is A-5). Validation is the security spine: a tenant may only pick a kind within its policy, and an
// openai_compatible base_url must already be on the platform allowlist (the §1903 data-egress boundary) — both
// rejected at SAVE time, not just fail-closed at call time.

import (
	"context"
	"encoding/base64"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// SecretBox seals/opens a per-scope secret (connector.Vault satisfies it structurally; wired at startup).
type SecretBox interface {
	Seal(scope uuid.UUID, plaintext []byte) ([]byte, error)
	Open(scope uuid.UUID, ciphertext []byte) ([]byte, error)
}

// ConfigService owns the admin/tenant AI-provider configuration surface.
type ConfigService struct {
	repo *Repository
	box  SecretBox
}

// NewConfigService builds the service.
func NewConfigService(repo *Repository, box SecretBox) *ConfigService {
	return &ConfigService{repo: repo, box: box}
}

// ProviderUpdate is the admin/tenant input. APIKey is plaintext, sealed before store and NEVER returned; an empty
// APIKey on update leaves the stored key unchanged is NOT supported here (A-4 keeps it simple: empty = keyless).
type ProviderUpdate struct {
	Kind    ProviderKind `json:"kind"`
	BaseURL string       `json:"base_url"`
	Model   string       `json:"model"`
	APIKey  string       `json:"api_key"`
}

// SaveResult carries the redacted view plus any non-blocking warnings (e.g. cleartext key over http, note 1).
type SaveResult struct {
	Provider ProviderView `json:"provider"`
	Warnings []string     `json:"warnings,omitempty"`
}

var knownKinds = map[ProviderKind]bool{KindAnthropic: true, KindOpenAICompatible: true, KindDisabled: true}

// validate checks the kind against an optional allow-set, validates/normalizes the endpoint against the allowlist,
// seals the key under scope, and returns the storable input plus warnings. allowed==nil skips the policy check
// (global-provider path — platform-admin is not policy-restricted).
func (s *ConfigService) validate(ctx context.Context, scope uuid.UUID, upd ProviderUpdate, allowed []string) (ProviderInput, []string, error) {
	if !knownKinds[upd.Kind] {
		return ProviderInput{}, nil, httpx.ErrBadRequest("unknown provider kind")
	}
	if allowed != nil && !contains(allowed, string(upd.Kind)) {
		return ProviderInput{}, nil, httpx.ErrForbidden("provider kind not permitted by tenant AI policy")
	}
	in := ProviderInput{Kind: upd.Kind, Model: upd.Model}
	var warnings []string

	switch upd.Kind {
	case KindOpenAICompatible:
		origin, scheme, host, port, err := normalizeEndpoint(upd.BaseURL)
		if err != nil {
			return ProviderInput{}, nil, httpx.ErrBadRequest("invalid base_url: " + err.Error())
		}
		ok, aerr := s.repo.IsAllowedEndpoint(ctx, scope, scheme, host, port)
		if aerr != nil {
			return ProviderInput{}, nil, aerr
		}
		if !ok {
			return ProviderInput{}, nil, httpx.ErrBadRequest("base_url is not on the platform allowlist (a platform admin must approve the endpoint first)")
		}
		in.BaseURL = origin
		// Note 1: a key that crosses a cleartext (http) endpoint is exposed on the wire — allowed for an approved
		// on-prem endpoint, but surface the exposure to the admin.
		if scheme == string(SchemeHTTP) && upd.APIKey != "" {
			warnings = append(warnings, "the API key will be sent over an unencrypted (http) endpoint — it is exposed in cleartext on the network")
		}
	case KindAnthropic, KindDisabled:
		if upd.BaseURL != "" {
			return ProviderInput{}, nil, httpx.ErrBadRequest("base_url is only valid for openai_compatible")
		}
	}

	if upd.APIKey != "" {
		ct, err := s.box.Seal(scope, []byte(upd.APIKey))
		if err != nil {
			return ProviderInput{}, nil, err
		}
		in.APIKeyRef = base64.StdEncoding.EncodeToString(ct)
	}
	return in, warnings, nil
}

// SetGlobalProvider sets the global default (platform-admin). Sealed under the system scope (uuid.Nil).
func (s *ConfigService) SetGlobalProvider(ctx context.Context, upd ProviderUpdate) (SaveResult, error) {
	in, warnings, err := s.validate(ctx, uuid.Nil, upd, nil)
	if err != nil {
		return SaveResult{}, err
	}
	if err := s.repo.SetGlobalProvider(ctx, in); err != nil {
		return SaveResult{}, err
	}
	return SaveResult{Provider: ProviderView{Kind: in.Kind, BaseURL: in.BaseURL, Model: in.Model, HasKey: in.APIKeyRef != "", Global: true}, Warnings: warnings}, nil
}

// SetTenantProvider sets a tenant's override (tenant-admin). Kind must be within the tenant's policy; sealed under
// the tenant scope.
func (s *ConfigService) SetTenantProvider(ctx context.Context, tenantID uuid.UUID, upd ProviderUpdate) (SaveResult, error) {
	allowed, err := s.repo.GetTenantPolicy(ctx, tenantID)
	if err != nil {
		return SaveResult{}, err
	}
	in, warnings, err := s.validate(ctx, tenantID, upd, allowed)
	if err != nil {
		return SaveResult{}, err
	}
	if err := s.repo.SetTenantProvider(ctx, tenantID, in); err != nil {
		return SaveResult{}, err
	}
	return SaveResult{Provider: ProviderView{Kind: in.Kind, BaseURL: in.BaseURL, Model: in.Model, HasKey: in.APIKeyRef != "", Global: false}, Warnings: warnings}, nil
}

// GetEffectiveProvider returns the tenant's effective (redacted) provider.
func (s *ConfigService) GetEffectiveProvider(ctx context.Context, tenantID uuid.UUID) (ProviderView, bool, error) {
	return s.repo.GetEffectiveProvider(ctx, tenantID)
}

// GetGlobalProvider returns the global default (redacted). Platform-admin.
func (s *ConfigService) GetGlobalProvider(ctx context.Context) (ProviderView, bool, error) {
	return s.repo.GetGlobalProvider(ctx)
}

// ListAllowedEndpoints / AddAllowedEndpoint / DeleteAllowedEndpoint — platform-admin trust list.
func (s *ConfigService) ListAllowedEndpoints(ctx context.Context) ([]AllowedEndpoint, error) {
	return s.repo.ListAllowedEndpoints(ctx)
}

// AddAllowedEndpoint validates + inserts a trust-list entry. host is lower-cased; scheme must be http|https.
func (s *ConfigService) AddAllowedEndpoint(ctx context.Context, scheme, host string, port int, note string) error {
	if scheme != string(SchemeHTTP) && scheme != string(SchemeHTTPS) {
		return httpx.ErrBadRequest("scheme must be http or https")
	}
	if host == "" {
		return httpx.ErrBadRequest("host is required")
	}
	if port < 0 || port > 65535 {
		return httpx.ErrBadRequest("invalid port")
	}
	return s.repo.AddAllowedEndpoint(ctx, scheme, lowerHost(host), port, note)
}

// DeleteAllowedEndpoint removes a trust-list entry.
func (s *ConfigService) DeleteAllowedEndpoint(ctx context.Context, id uuid.UUID) error {
	return s.repo.DeleteAllowedEndpoint(ctx, id)
}

// SetTenantPolicy sets a tenant's allowed_kinds (platform-admin). Kinds must all be known.
func (s *ConfigService) SetTenantPolicy(ctx context.Context, tenantID uuid.UUID, kinds []string) error {
	if len(kinds) == 0 {
		return httpx.ErrBadRequest("allowed_kinds must not be empty")
	}
	for _, k := range kinds {
		if !knownKinds[ProviderKind(k)] {
			return httpx.ErrBadRequest("unknown provider kind in allowed_kinds: " + k)
		}
	}
	return s.repo.SetTenantPolicy(ctx, tenantID, kinds)
}

// GetTenantPolicy returns a tenant's allowed_kinds.
func (s *ConfigService) GetTenantPolicy(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	return s.repo.GetTenantPolicy(ctx, tenantID)
}

func lowerHost(h string) string {
	b := []byte(h)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
