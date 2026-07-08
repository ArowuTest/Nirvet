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
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/google/uuid"
)

// PackSchemaVersion is the evidence-pack format version (bump on breaking changes).
const PackSchemaVersion = "1.0"

// Pack is a complete evidence bundle for a single incident.
type Pack struct {
	SchemaVersion string                       `json:"schema_version"`
	GeneratedAt   time.Time                    `json:"generated_at"`
	GeneratedBy   string                       `json:"generated_by"`
	TenantID      uuid.UUID                    `json:"tenant_id"`
	Incident      *incident.Incident           `json:"incident"`
	Timeline      []incident.TimelineEntry     `json:"timeline"`
	Alerts        []alert.Alert                `json:"alerts"`
	Events        []eventstore.NormalizedEvent `json:"events"`
	Audit         []audit.LogEntry             `json:"audit"`
	Manifest      Manifest                     `json:"manifest"`
}

// Manifest carries integrity metadata: per-section SHA-256 checksums and counts, and
// an overall checksum over the section checksums. Verifying a pack = recomputing the
// section checksums over each section and comparing to the manifest.
type Manifest struct {
	Algorithm       string            `json:"algorithm"` // "sha256"
	SectionChecksum map[string]string `json:"section_checksum"`
	Counts          map[string]int    `json:"counts"`
	PackChecksum    string            `json:"pack_checksum"`
}
