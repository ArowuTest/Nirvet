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
const CanonicalSchemaVersion = "1.0"

// NormalizedEvent is an OCSF-inspired security event (doc 02 §4, ADR-0006). Every
// source normalizer emits this canonical shape. Structured key fields are
// first-class columns; the full normalized body lives in Data. The raw event is
// preserved separately (RawPointer + Checksum) for evidence/defensibility.
type NormalizedEvent struct {
	ID            uuid.UUID    `json:"id"`
	TenantID      uuid.UUID    `json:"tenant_id"`
	SchemaVersion string       `json:"schema_version"` // ADR-0006 canonical schema version
	DedupeKey     string       `json:"dedupe_key"`     // source + native id + payload hash
	Source        string       `json:"source"`
	ConnectorID *uuid.UUID     `json:"connector_id,omitempty"`
	CollectedAt time.Time      `json:"collected_at"`
	ObservedAt  time.Time      `json:"observed_at"`
	ClassName   string         `json:"class_name"`
	ActivityName string        `json:"activity_name"`
	Severity    string         `json:"severity"`   // informational|low|medium|high|critical
	Confidence  int            `json:"confidence"` // 0-100
	ActorRef    string         `json:"actor_ref"`  // user/host/ip
	TargetRef   string         `json:"target_ref"` // resource/account/host
	Action      string         `json:"action"`
	Outcome     string         `json:"outcome"`
	RawPointer  string         `json:"raw_pointer"` // object-store key of the raw event
	Checksum    string         `json:"checksum"`    // sha256 of raw
	Data        map[string]any `json:"data"`        // full normalized payload
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
}
