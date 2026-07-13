// Package connector is the integration framework (SRS §6.4, §8; ADR-0004).
// Connectors pull telemetry from / push actions to customer tools (M365, Entra,
// Defender, EDR, cloud, firewalls, ticketing). Credentials are stored encrypted
// via the SecretCipher (audited Vault.Open) and decrypted only in memory at run time.
//
// Connectors advertise a granular Capability set (pull_alerts, isolate_endpoint,
// disable_user, create_ticket, …) from a closed, validated vocabulary that drives
// licensing, UI display and entitlement. Live connectors include Microsoft 365 /
// Entra sign-in pull, Defender (pull + isolate/release + IOC), Entra (disable/enable
// user), syslog/webhook ingress and the ServiceNow/Jira ITSM (create_ticket) path.
package connector

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Direction of a connector's capability.
type Direction string

const (
	DirectionRead   Direction = "read"   // pull telemetry
	DirectionAction Direction = "action" // push response actions (authority-to-act gated)
)

// Capability is one granular thing a connector can do. The coarse read|action Direction can't express that,
// say, Defender both pulls telemetry AND isolates hosts AND runs hunt queries — so a connector advertises an
// explicit SET of these (external-review). The vocabulary is CLOSED and validated (KnownCapability + the
// TestAllCapabilitiesAreKnown fence): a typo'd capability can't silently ship, because licensing, UI display,
// and entitlement all key off these exact tokens. Underlying string → serialises unchanged on the catalogue.
type Capability string

const (
	// Read / ingest.
	CapPullAlerts     Capability = "pull_alerts"     // poll the vendor API for alerts/telemetry
	CapReceiveWebhook Capability = "receive_webhook" // accept vendor-pushed events on an ingress endpoint
	CapReceiveSyslog  Capability = "receive_syslog"  // accept RFC5424/3164 syslog on the listener
	CapRunQuery       Capability = "run_query"       // execute an ad-hoc query against the source (e.g. KQL)
	CapRunHunt        Capability = "run_hunt"        // execute a saved/threat-hunt query against the source
	CapRetrieveAsset  Capability = "retrieve_asset"  // fetch device/machine/asset detail from the source
	// Action (each authority-to-act gated in soar before execution).
	CapIsolateEndpoint Capability = "isolate_endpoint" // network-contain a host (UI label: "Contain Endpoint")
	CapReleaseEndpoint Capability = "release_endpoint" // lift a host containment
	CapDisableUser     Capability = "disable_user"     // disable an identity
	CapEnableUser      Capability = "enable_user"      // re-enable an identity
	CapPushIOC         Capability = "push_ioc"         // push an indicator/custom-detection to the source
	CapCreateTicket    Capability = "create_ticket"    // create/mirror a ticket in the tenant's ITSM
	// Generic fallback for an action connector with no finer classification yet.
	CapAction Capability = "action"
)

// knownCapabilities is the closed vocabulary. A descriptor may only advertise a member of this set; the CI
// fence TestAllCapabilitiesAreKnown fails the build otherwise, so the licensing/UI contract can't drift.
var knownCapabilities = map[Capability]bool{
	CapPullAlerts: true, CapReceiveWebhook: true, CapReceiveSyslog: true, CapRunQuery: true,
	CapRunHunt: true, CapRetrieveAsset: true, CapIsolateEndpoint: true, CapReleaseEndpoint: true,
	CapDisableUser: true, CapEnableUser: true, CapPushIOC: true, CapCreateTicket: true, CapAction: true,
}

// KnownCapability reports whether c is part of the closed capability vocabulary.
func KnownCapability(c Capability) bool { return knownCapabilities[c] }

// Descriptor describes a connector type in the catalogue (backlog: Integration Roadmap).
type Descriptor struct {
	Key      string `json:"key"`      // "microsoft-365", "entra-id", "defender", ...
	Name     string `json:"name"`     // R6: explicit snake_case tags — this is serialised by the
	Category string `json:"category"` // /connectors/catalogue endpoint; tag-less fields would render
	// Direction is the coarse legacy classification (read|action) kept for back-compat.
	Direction Direction `json:"direction"`
	// Capabilities is the EXPLICIT capability set (external-review): a single read/action direction can't
	// express that Defender both pulls telemetry AND takes response actions. Drives licensing, UI display,
	// entitlement + authority-to-act checks, and connector-health surfacing. Every entry is a member of the
	// closed Capability vocabulary (validated by TestAllCapabilitiesAreKnown).
	Capabilities []Capability `json:"capabilities"`
	Phase        string       `json:"phase"` // Identity|EDR|Cloud|Firewall|Ticketing|Generic ; MVP|V1|V2
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

// capabilitiesByKey is the explicit per-connector capability set. Read connectors pull telemetry;
// Defender/Entra are dual (telemetry + response); generic ingress connectors receive pushes; ITSM
// connectors create tickets. Only capabilities the connector genuinely backs (or is wired to back) are
// advertised — the set is honest, not aspirational.
var capabilitiesByKey = map[string][]Capability{
	"microsoft-365": {CapPullAlerts},
	"entra-id":      {CapDisableUser, CapEnableUser},
	// Defender is the richest: telemetry + endpoint containment + advanced-hunting query + machine detail +
	// custom-indicator (IOC) push — the coarse read|action can't express any of that.
	"defender":           {CapPullAlerts, CapIsolateEndpoint, CapReleaseEndpoint, CapRunQuery, CapRetrieveAsset, CapPushIOC},
	"syslog":             {CapReceiveSyslog},
	"webhook":            {CapReceiveWebhook},
	"crowdstrike-falcon": {CapReceiveWebhook, CapPullAlerts, CapRetrieveAsset},
	"okta":               {CapReceiveWebhook},
	"palo-alto":          {CapReceiveWebhook},
	"aws-guardduty":      {CapReceiveWebhook},
	"azure-sentinel":     {CapReceiveWebhook, CapRunQuery, CapRunHunt}, // SIEM: query + threat-hunt native
	"gcp-scc":            {CapReceiveWebhook},
	// ITSM connectors — outbound ticket creation (internal/ticketing subsystem; SRS §6.16).
	"servicenow": {CapCreateTicket},
	"jira":       {CapCreateTicket},
}

// Registry holds available connector descriptors (MVP catalogue). Capabilities are attached per key.
func Registry() []Descriptor {
	ds := registryBase()
	for i := range ds {
		if caps, ok := capabilitiesByKey[ds[i].Key]; ok {
			ds[i].Capabilities = caps
		} else if ds[i].Direction == DirectionAction {
			ds[i].Capabilities = []Capability{CapAction}
		} else {
			ds[i].Capabilities = []Capability{CapPullAlerts}
		}
	}
	return ds
}

func registryBase() []Descriptor {
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
		// ITSM (outbound) — Nirvet mirrors incidents into the tenant's system of record (internal/ticketing).
		{Key: "servicenow", Name: "ServiceNow", Category: "Ticketing", Direction: DirectionAction, Phase: "V1"},
		{Key: "jira", Name: "Jira", Category: "Ticketing", Direction: DirectionAction, Phase: "V1"},
	}
}

// Vault stores and retrieves connector credentials, encrypted per tenant (ADR-0004). Open is the single
// AUDITED chokepoint for connector-credential decrypts (GC-1): ADR-0004 §6 mandates that every decrypt/use
// of a connector credential writes an immutable audit event — so the decrypt path itself audits, rather than
// relying on each caller to remember. A CI fence (scripts/check-connector-decrypt-audit.sh) forbids any
// other decrypt of connector secrets, mirroring the session-mint single-path fence.
type Vault struct {
	cipher crypto.SecretCipher
	db     *database.DB // nil in unit tests => audit skipped; wired in prod via WithDB
}

// NewVault builds the credential vault.
func NewVault(cipher crypto.SecretCipher) *Vault { return &Vault{cipher: cipher} }

// WithDB wires the DB so Open can write the ADR-0004 credential-decrypt audit event. Returns the vault.
func (v *Vault) WithDB(db *database.DB) *Vault { v.db = db; return v }

// Seal encrypts a secret for storage.
func (v *Vault) Seal(tenantID uuid.UUID, secret []byte) ([]byte, error) {
	return v.cipher.Encrypt(tenantID, secret)
}

// Open decrypts a stored connector secret (in memory only; never log the result) and audits the access
// (ADR-0004 §6). purpose describes why (poll/probe/soar_action). The audit is a system-actor event in the
// tenant's context; a failed audit write must not silently drop a decrypt from the trail, so it fails the op.
func (v *Vault) Open(ctx context.Context, tenantID, connectorID uuid.UUID, purpose string, ciphertext []byte) ([]byte, error) {
	plain, err := v.cipher.Decrypt(tenantID, ciphertext)
	if err != nil {
		return nil, err
	}
	if v.db != nil {
		if aerr := v.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
			return audit.Record(ctx, tx, audit.Entry{
				Action: "connector.credential_decrypt", Target: "connector:" + connectorID.String(),
				Metadata: map[string]any{"purpose": purpose},
			})
		}); aerr != nil {
			return nil, aerr
		}
	}
	return plain, nil
}
