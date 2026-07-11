// Package eventstore is the telemetry store abstraction (ADR-0002). The MVP
// backend is Postgres; the V1 backend is ClickHouse. Callers depend only on this
// interface so the backend can be swapped without touching detection/search code.
package eventstore

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// CanonicalSchemaVersion is the current version of the canonical event schema
// (ADR-0006). Every normalized event carries it so the schema can evolve without a
// big-bang migration; consumers may branch on it and backfills can target a version.
// v1.1: promoted mitre/vendor/product from the data payload to first-class columns.
const CanonicalSchemaVersion = "1.1"

// NormalizedEvent is an OCSF-inspired security event (doc 02 §4, ADR-0006). Every
// source normalizer emits this canonical shape. Structured key fields are
// first-class columns; the full normalized body lives in Data. The raw event is
// preserved separately (RawPointer + Checksum) for evidence/defensibility.
type NormalizedEvent struct {
	ID            uuid.UUID      `json:"id"`
	TenantID      uuid.UUID      `json:"tenant_id"`
	SchemaVersion string         `json:"schema_version"` // ADR-0006 canonical schema version
	DedupeKey     string         `json:"dedupe_key"`     // source + native id + payload hash
	Source        string         `json:"source"`
	ConnectorID   *uuid.UUID     `json:"connector_id,omitempty"`
	CollectedAt   time.Time      `json:"collected_at"`
	ObservedAt    time.Time      `json:"observed_at"`
	ClassName     string         `json:"class_name"`
	ActivityName  string         `json:"activity_name"`
	Severity      string         `json:"severity"`   // informational|low|medium|high|critical
	Confidence    int            `json:"confidence"` // 0-100
	ActorRef      string         `json:"actor_ref"`  // user/host/ip
	TargetRef     string         `json:"target_ref"` // resource/account/host
	Action        string         `json:"action"`
	Outcome       string         `json:"outcome"`
	MITRE         []string       `json:"mitre"`       // ATT&CK technique ids (v1.1, first-class)
	Vendor        string         `json:"vendor"`      // e.g. CrowdStrike (v1.1, first-class)
	Product       string         `json:"product"`     // e.g. Falcon (v1.1, first-class)
	RawPointer    string         `json:"raw_pointer"` // object-store key of the raw event
	Checksum      string         `json:"checksum"`    // sha256 of raw
	Data          map[string]any `json:"data"`        // full normalized payload
}

// MITRECount is an ATT&CK technique frequency (analytics over the mitre column).
type MITRECount struct {
	Technique string `json:"technique"`
	Count     int    `json:"count"`
}

// Query filters a tenant's events.
type Query struct {
	From     time.Time
	To       time.Time
	Severity string
	Search   string // free-text over class/action/refs
	Limit    int
}

// EventStore appends and queries normalized security events, always tenant-scoped.
type EventStore interface {
	// Append inserts events for a tenant, idempotent on DedupeKey (ADR-0003).
	// Returns the number of events NEWLY inserted (duplicates are skipped), so
	// callers can run detection only on new events and stay idempotent on retry.
	Append(ctx context.Context, tenantID uuid.UUID, events []NormalizedEvent) (int, error)
	// Query returns a tenant's events matching q.
	Query(ctx context.Context, tenantID uuid.UUID, q Query) ([]NormalizedEvent, error)
	// GetByIDs returns the tenant's events with the given ids (evidence-pack
	// assembly). Missing ids are simply absent; order is not guaranteed.
	GetByIDs(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) ([]NormalizedEvent, error)
	// CountSince returns the number of a tenant's events observed at or after
	// `since` — used by reporting/dashboards so counts are correct on any backend.
	CountSince(ctx context.Context, tenantID uuid.UUID, since time.Time) (int, error)
	// TopMITRE returns the most frequent ATT&CK techniques for a tenant since
	// `since` (analytics over the first-class mitre column, ADR-0006 v1.1).
	TopMITRE(ctx context.Context, tenantID uuid.UUID, since time.Time, limit int) ([]MITRECount, error)
	// Ping verifies backend connectivity — used by the readiness probe so a degraded telemetry store is
	// surfaced rather than discovered on the first query (external-review dependency-aware /readyz).
	Ping(ctx context.Context) error
}
