// Package evidence assembles tamper-evident evidence packs for an incident
// (SRS §6.13). A pack is a self-contained, read-only bundle — the case, its
// investigation timeline, the alerts promoted into it, the underlying normalized
// events, and the relevant audit trail — plus a manifest of SHA-256 checksums so a
// recipient (customer, auditor, court) can verify the bundle was not altered after
// export. It composes the existing case/alert/event/audit stores; it owns no table.
package evidence

import (
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/vulnerability"
	"github.com/google/uuid"
)

// PackSchemaVersion is the evidence-pack format version (bump on breaking changes).
const PackSchemaVersion = "1.0"

// Pack is a complete evidence bundle for a single incident.
type Pack struct {
	SchemaVersion   string                       `json:"schema_version"`
	GeneratedAt     time.Time                    `json:"generated_at"`
	GeneratedBy     string                       `json:"generated_by"`
	TenantID        uuid.UUID                    `json:"tenant_id"`
	Incident        *incident.Incident           `json:"incident"`
	Timeline        []incident.TimelineEntry     `json:"timeline"`
	Alerts          []alert.Alert                `json:"alerts"`
	Events          []eventstore.NormalizedEvent `json:"events"`
	Assets          []asset.Asset                `json:"assets"`          // affected assets (§6.15), matched by alert refs
	Vulnerabilities []vulnerability.Vuln         `json:"vulnerabilities"` // open vulns on those assets (§6.15 ASSET-002/007)
	Audit           []audit.LogEntry             `json:"audit"`
	Manifest        Manifest                     `json:"manifest"`
}

// Manifest carries integrity metadata: per-section SHA-256 checksums and counts, a
// pack digest that folds the ENVELOPE metadata (generated_at/by, tenant, schema) with
// the section checksums, and an Ed25519 signature over that digest (R2 H-B). Verifying
// a pack = recompute each section checksum over its data, recompute the digest, and
// verify the signature against a TRUSTED public key (obtained out-of-band, e.g. the
// platform's published key) — see Verify.
type Manifest struct {
	Algorithm       string            `json:"algorithm"` // section checksum algorithm: "sha256"
	SectionChecksum map[string]string `json:"section_checksum"`
	Counts          map[string]int    `json:"counts"`
	PackDigest      string            `json:"pack_digest"`         // hex sha256 over envelope + section checksums (the signed message's hash)
	Signature       *Signature        `json:"signature,omitempty"` // Ed25519 signature over the canonical digest input
}

// Signature is a detached Ed25519 signature over a pack's canonical digest input.
type Signature struct {
	Algorithm string `json:"algorithm"`  // "ed25519"
	PublicKey string `json:"public_key"` // base64 — for convenience; verification MUST use a trusted key
	Value     string `json:"value"`      // base64 signature
}
