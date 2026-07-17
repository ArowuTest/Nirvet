package connector

// §6.11 SOAR slice C — the real CredDecryptor. The SOAR two-phase supervisor decrypts a tenant's
// connector credentials in Phase B and hands them to the vendor Actioner. Slice B wired this seam as
// nil (dormant); this makes the bytes real: vault-open the tenant's connector secret and return an
// opaque JSON credential bundle the Actioner unmarshals. Tenant-scoped (RLS) throughout.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Credentials is the decrypted credential bundle a SOAR containment Actioner needs to authenticate an
// outbound vendor call. JSON-encoded so it passes opaquely through the supervisor's []byte creds
// channel — the supervisor never inspects it; only the vendor Actioner unmarshals it.
type Credentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	AzureTenant  string `json:"azure_tenant"`
	// Okta identity-containment vendor (G1): SSWS API token + the tenant's Okta org base URL.
	OktaOrgURL string `json:"okta_org_url"`
	OktaToken  string `json:"okta_token"`
	// CrowdStrike Falcon EDR vendor (G1 #2): OAuth2 client-credentials reuse ClientID/ClientSecret; the API base
	// is REGION-specific (US-1 api.crowdstrike.com, US-2, EU-1, GovCloud api.laggar.gcw.crowdstrike.com — GovCloud
	// matters for the Ghana-sovereign posture). Empty base ⇒ US-1 default.
	CrowdStrikeBaseURL string `json:"crowdstrike_base_url"`
}

// connectorSecret is a tenant connector's sealed credential + config for an authorized action call.
type connectorSecret struct {
	ID     uuid.UUID
	Secret []byte
	Config map[string]any
}

// getCredentialsByKind returns the newest ENABLED connector of a kind for a tenant, with its sealed
// secret + config, tenant-scoped (RLS). Errors if the tenant has no such enabled connector with
// stored credentials — a containment step for a tenant that never configured the vendor fails closed.
func (r *Repository) getCredentialsByKind(ctx context.Context, tenantID uuid.UUID, kind string) (*connectorSecret, error) {
	var cs connectorSecret
	var cfg []byte
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, secret_ciphertext, config FROM connector_configs
			  WHERE tenant_id=$1 AND kind=$2 AND enabled=true AND secret_ciphertext IS NOT NULL
			  ORDER BY created_at DESC LIMIT 1`, tenantID, kind).Scan(&cs.ID, &cs.Secret, &cfg)
	})
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("no enabled %q connector with credentials for tenant", kind)
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(cfg, &cs.Config)
	return &cs, nil
}

// CredentialResolver vault-decrypts a tenant's connector credentials for an authorized SOAR action.
// It structurally implements soar.CredDecryptor (ConnectorCreds), wired into the SOAR supervisor at
// startup so a real vendor Actioner receives live credentials in Phase B.
type CredentialResolver struct {
	repo  *Repository
	vault *Vault
}

// NewCredentialResolver builds the resolver from a connector repository + vault.
func NewCredentialResolver(repo *Repository, vault *Vault) *CredentialResolver {
	return &CredentialResolver{repo: repo, vault: vault}
}

// ConnectorCreds returns the tenant's enabled connector-of-kind credentials as an opaque JSON bundle
// (connector.Credentials). connectorKey is the SOAR ConnectorKey (e.g. "defender").
func (c *CredentialResolver) ConnectorCreds(ctx context.Context, tenantID uuid.UUID, connectorKey string) ([]byte, error) {
	cs, err := c.repo.getCredentialsByKind(ctx, tenantID, connectorKey)
	if err != nil {
		return nil, err
	}
	secret, err := c.vault.Open(ctx, tenantID, cs.ID, "soar_action", cs.Secret)
	if err != nil {
		return nil, err
	}
	clientID, _ := cs.Config["client_id"].(string)
	azTenant, _ := cs.Config["azure_tenant"].(string)
	return json.Marshal(Credentials{ClientID: clientID, ClientSecret: string(secret), AzureTenant: azTenant})
}
