// Package ingestion receives security events, persists the raw event immutably,
// and enqueues normalization (ADR-0003). A worker then normalizes to the
// OCSF-inspired model, stores in the EventStore, and runs detection.
package ingestion

import (
	"time"

	"github.com/google/uuid"
)

// IngestInput is a single event submitted to the platform (webhook/API). In a
// real connector this is produced by a source-specific parser; here it is already
// close to the normalized shape for the scaffold.
type IngestInput struct {
	Source       string         `json:"source"`
	NativeID     string         `json:"native_id"`
	ClassName    string         `json:"class_name"`
	ActivityName string         `json:"activity_name"`
	Severity     string         `json:"severity"` // informational|low|medium|high|critical
	Confidence   int            `json:"confidence"`
	ActorRef     string         `json:"actor_ref"`
	TargetRef    string         `json:"target_ref"`
	Action       string         `json:"action"`
	Outcome      string         `json:"outcome"`
	ObservedAt   time.Time      `json:"observed_at"`
	Data         map[string]any `json:"data"`
}

// RawEvent is the immutable raw record (evidence). The payload is stored in the
// cloud-agnostic BlobStore (ADR-0002/0005); the row holds the URI + checksum.
type RawEvent struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	Source     string
	DedupeKey  string
	Checksum   string
	BlobURI    string
	Payload    []byte // optional; nil when stored in the blob store
	ReceivedAt time.Time
}

// normalizeJob is the queued payload for the normalize worker.
type normalizeJob struct {
	RawID     uuid.UUID   `json:"raw_id"`
	DedupeKey string      `json:"dedupe_key"`
	Checksum  string      `json:"checksum"`
	Input     IngestInput `json:"input"`
}
