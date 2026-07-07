package ticketing

import (
	"context"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Service manages ticketing connections and mirrors incidents to the ITSM.
type Service struct {
	repo   *Repository
	cipher crypto.SecretCipher
}

// NewService builds the service.
func NewService(repo *Repository, cipher crypto.SecretCipher) *Service {
	return &Service{repo: repo, cipher: cipher}
}

// CreateConnection validates and stores a connection (credential sealed).
func (s *Service) CreateConnection(ctx context.Context, tenantID uuid.UUID, in CreateInput) (*Connection, error) {
	if _, err := ProviderFor(in.Provider); err != nil {
		return nil, httpx.ErrBadRequest("provider must be servicenow or jira")
	}
	if in.BaseURL == "" || in.Credential == "" {
		return nil, httpx.ErrBadRequest("base_url and credential are required")
	}
	if in.Config == nil {
		in.Config = map[string]any{}
	}
	sealed, err := s.cipher.Encrypt(tenantID, []byte(in.Credential))
	if err != nil {
		return nil, httpx.ErrInternal("could not seal credential")
	}
	c := &Connection{
		ID: uuid.New(), TenantID: tenantID, Provider: in.Provider,
		BaseURL: strings.TrimSpace(in.BaseURL), AuthUser: in.AuthUser,
		Credential: sealed, Config: in.Config, Enabled: true,
	}
	if err := s.repo.Create(ctx, c); err != nil {
		return nil, httpx.ErrInternal("could not save connection")
	}
	return c, nil
}

// ListConnections returns a tenant's connections.
func (s *Service) ListConnections(ctx context.Context, tenantID uuid.UUID) ([]Connection, error) {
	return s.repo.List(ctx, tenantID)
}

// DeleteConnection removes a connection.
func (s *Service) DeleteConnection(ctx context.Context, tenantID, id uuid.UUID) error {
	if err := s.repo.Delete(ctx, tenantID, id); err != nil {
		return httpx.ErrNotFound("connection not found")
	}
	return nil
}

// MirrorIncident creates a ticket in the tenant's ITSM for an incident and returns
// its external ref. Returns ("", "", nil) when the tenant has no ticketing
// connection configured — the caller treats that as "nothing to do". Satisfies
// incident.Ticketer. Credential is decrypted in memory only, never logged.
func (s *Service) MirrorIncident(ctx context.Context, tenantID uuid.UUID, title, severity, body string) (ref, url string, err error) {
	conn, err := s.repo.EnabledForTenant(ctx, tenantID)
	if err != nil {
		return "", "", err
	}
	if conn == nil {
		return "", "", nil // no ITSM configured for this tenant
	}
	provider, err := ProviderFor(conn.Provider)
	if err != nil {
		return "", "", err
	}
	secret, err := s.cipher.Decrypt(tenantID, conn.Credential)
	if err != nil {
		return "", "", err
	}
	r, err := provider.Create(ctx, conn, string(secret), Ticket{Title: title, Description: body, Severity: severity})
	if err != nil {
		return "", "", err
	}
	return r.ID, r.URL, nil
}
