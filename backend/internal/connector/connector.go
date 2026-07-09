// Package connector is the integration framework (SRS §6.4, §8; ADR-0004).
// Connectors pull telemetry from / push actions to customer tools (M365, Entra,
// Defender, EDR, cloud, firewalls, ticketing). Credentials are stored encrypted
// via the SecretCipher and decrypted only in memory at run time.
//
// STATUS: scaffold. Interfaces + registry defined; concrete MVP connectors
// (Microsoft 365, Entra ID, Defender) are TODO. Not yet wired into routes.
package connector

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/google/uuid"
)

// Direction of a connector's capability.
type Direction string

const (
	DirectionRead   Direction = "read"   // pull telemetry
	DirectionAction Direction = "action" // push response actions (authority-to-act gated)
)

// Descriptor describes a connector type in the catalogue (backlog: Integration Roadmap).
type Descriptor struct {
	Key       string    `json:"key"`       // "microsoft-365", "entra-id", "defender", ...
	Name      string    `json:"name"`      // R6: explicit snake_case tags — this is serialised by the
	Category  string    `json:"category"`  // /connectors/catalogue endpoint; tag-less fields would render
	Direction Direction `json:"direction"` // as PascalCase, inconsistent with every other API payload.
	Phase     string    `json:"phase"`     // Identity|EDR|Cloud|Firewall|Ticketing|Generic ; MVP|V1|V2
}

// Puller pulls events from a source into the platform (feeds ingestion → EventStore).
type Puller interface {
	Descriptor() Descriptor
	// Pull fetches new events since the checkpoint; returns normalized events + next checkpoint.
	Pull(ctx context.Context, tenantID uuid.UUID, checkpoint string) ([]eventstore.NormalizedEvent, string, error)
}

// Actioner executes a response action in the source (SOAR action connector).
// Actions must be gated by tenant authority-to-act before this is called (soar package).
type Actioner interface {
	Descriptor() Descriptor
	// Execute performs an action (e.g. isolate device, disable user) with scoped creds.
	Execute(ctx context.Context, tenantID uuid.UUID, action string, params map[string]any) error
}

// Registry holds available connector descriptors (MVP catalogue).
func Registry() []Descriptor {
	return []Descriptor{
		{Key: "microsoft-365", Name: "Microsoft 365", Category: "Productivity", Direction: DirectionRead, Phase: "MVP"},
		{Key: "entra-id", Name: "Entra ID", Category: "Identity", Direction: DirectionAction, Phase: "MVP"},
		{Key: "defender", Name: "Microsoft Defender", Category: "EDR", Direction: DirectionAction, Phase: "MVP"},
		{Key: "syslog", Name: "Syslog", Category: "Generic", Direction: DirectionRead, Phase: "MVP"},
		{Key: "webhook", Name: "Webhook/API", Category: "Generic", Direction: DirectionRead, Phase: "MVP"},
		// Telemetry sources with a source normalizer (ingestion.Normalize registry).
		// They ingest via the generic webhook now; native pull loops are per-vendor V1.
		{Key: "crowdstrike-falcon", Name: "CrowdStrike Falcon", Category: "EDR", Direction: DirectionRead, Phase: "V1"},
		{Key: "okta", Name: "Okta", Category: "Identity", Direction: DirectionRead, Phase: "V1"},
		{Key: "palo-alto", Name: "Palo Alto Networks", Category: "Firewall", Direction: DirectionRead, Phase: "V1"},
		{Key: "aws-guardduty", Name: "AWS GuardDuty", Category: "Cloud", Direction: DirectionRead, Phase: "V1"},
		{Key: "azure-sentinel", Name: "Microsoft Sentinel", Category: "Cloud", Direction: DirectionRead, Phase: "V1"},
		{Key: "gcp-scc", Name: "Google Security Command Center", Category: "Cloud", Direction: DirectionRead, Phase: "V1"},
	}
}

// Vault stores and retrieves connector credentials, encrypted per tenant (ADR-0004).
// TODO: persist ciphertext in a connector_credentials table; here it only wraps the cipher.
type Vault struct{ cipher crypto.SecretCipher }

// NewVault builds the credential vault.
func NewVault(cipher crypto.SecretCipher) *Vault { return &Vault{cipher: cipher} }

// Seal encrypts a secret for storage.
func (v *Vault) Seal(tenantID uuid.UUID, secret []byte) ([]byte, error) {
	return v.cipher.Encrypt(tenantID, secret)
}

// Open decrypts a stored secret (in memory only; never log the result).
func (v *Vault) Open(tenantID uuid.UUID, ciphertext []byte) ([]byte, error) {
	return v.cipher.Decrypt(tenantID, ciphertext)
}
