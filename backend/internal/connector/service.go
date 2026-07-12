package connector

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"

	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Service manages connectors and authenticated webhook ingestion.
type Service struct {
	repo   *Repository
	vault  *Vault
	ingest *ingestion.Service

	// Test-connection probe seams. Prod leaves these zero: a nil client becomes netsafe.SafeClient (SSRF-safe)
	// and empty URLs become the real Microsoft endpoints. Tests assign them (in-package) to reach a mock server —
	// exactly the poller's pattern; the prod path is unchanged.
	probeHTTP     *http.Client
	probeTokenURL string
	probeGraphURL string

	// #188 credential-expiry reminder seams (optional; nil in unit tests that don't sweep). escalation routes a
	// reminder to the tenant's escalation-matrix contacts (implemented by tenant.Service); enqueuer durably queues
	// it on the notify outbox. Both nil ⇒ SweepCredExpiry falls back to the log channel so a reminder is never
	// silently dropped.
	escalation CredEscalationResolver
	enqueuer   CredEnqueuer
}

// NewService builds the service.
func NewService(repo *Repository, vault *Vault, ingest *ingestion.Service) *Service {
	return &Service{repo: repo, vault: vault, ingest: ingest}
}

// CreateInput creates a connector.
type CreateInput struct {
	Kind      Kind           `json:"kind"`
	Name      string         `json:"name"`
	Direction string         `json:"direction"`
	Secret    string         `json:"secret"` // e.g. OAuth client secret / API key (vault-sealed)
	Config    map[string]any `json:"config"`
}

// CreateResult carries the connector and, for webhooks, the one-time source key.
type CreateResult struct {
	Connector *ConnectorConfig `json:"connector"`
	SourceKey string           `json:"source_key,omitempty"` // shown ONCE
	IngestURL string           `json:"ingest_url,omitempty"`
}

var validKinds = map[Kind]bool{
	KindMicrosoft365: true, KindEntraID: true, KindDefender: true, KindSyslog: true, KindWebhook: true,
	KindOsquery: true, KindWazuh: true, // §6.4/§6.5 #118 host-telemetry push sources
}

// Create provisions a connector. Secrets are vault-sealed; webhooks get a key.
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, in CreateInput) (*CreateResult, error) {
	if !validKinds[in.Kind] {
		return nil, httpx.ErrBadRequest("invalid connector kind")
	}
	if in.Name == "" {
		return nil, httpx.ErrBadRequest("name is required")
	}
	if in.Direction == "" {
		in.Direction = "read"
	}
	if in.Config == nil {
		in.Config = map[string]any{}
	}

	var sealed []byte
	if in.Secret != "" {
		b, err := s.vault.Seal(tenantID, []byte(in.Secret))
		if err != nil {
			return nil, httpx.ErrInternal("could not seal secret")
		}
		sealed = b
	}

	var sourceKey, keyHash string
	if in.Kind == KindWebhook {
		var kerr error
		if sourceKey, kerr = randomKey(); kerr != nil {
			return nil, httpx.ErrInternal("could not generate connector key")
		}
		keyHash = hashKey(sourceKey)
	}

	c := &ConnectorConfig{
		ID: uuid.New(), TenantID: tenantID, Kind: in.Kind, Name: in.Name,
		Direction: in.Direction, Enabled: true, Config: in.Config, Health: "unknown",
	}
	if err := s.repo.Create(ctx, c, sealed, keyHash); err != nil {
		return nil, httpx.ErrInternal("could not create connector")
	}
	res := &CreateResult{Connector: c}
	if in.Kind == KindWebhook {
		res.SourceKey = sourceKey
		res.IngestURL = "/ingest/webhook/" + c.ID.String()
	}
	return res, nil
}

// List returns the tenant's connectors.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]ConnectorConfig, error) {
	return s.repo.List(ctx, tenantID)
}

// Delete removes a connector.
func (s *Service) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	if err := s.repo.Delete(ctx, tenantID, id); err != nil {
		return httpx.ErrNotFound("connector not found")
	}
	return nil
}

// IngestWebhook authenticates a webhook post by source key and ingests events
// into the connector's tenant. Returns the number accepted.
func (s *Service) IngestWebhook(ctx context.Context, connectorID uuid.UUID, providedKey string, events []ingestion.IngestInput) (int, error) {
	wi, err := s.repo.FindForWebhook(ctx, connectorID)
	if err != nil {
		return 0, httpx.ErrNotFound("connector not found")
	}
	if !wi.Enabled || wi.Kind != string(KindWebhook) {
		return 0, httpx.ErrForbidden("connector not accepting webhook ingestion")
	}
	if subtle.ConstantTimeCompare([]byte(hashKey(providedKey)), []byte(wi.KeyHash)) != 1 {
		return 0, httpx.ErrUnauthorized("invalid source key")
	}
	accepted := 0
	for i := range events {
		if events[i].Source == "" {
			events[i].Source = "webhook"
		}
		if _, err := s.ingest.Ingest(ctx, wi.TenantID, events[i]); err != nil {
			return accepted, err
		}
		accepted++
	}
	_ = s.repo.MarkSuccess(ctx, wi.TenantID, connectorID)
	return accepted, nil
}

// randomKey mints a 256-bit webhook source key. R6: propagate a crypto/rand failure rather
// than silently returning an all-zero (predictable) key that would authenticate any caller.
func randomKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashKey(k string) string {
	sum := sha256.Sum256([]byte(k))
	return hex.EncodeToString(sum[:])
}
