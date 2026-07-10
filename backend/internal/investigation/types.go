package investigation

// §6.9 #124 I-1 — the hunt-query result projection. Deliberately a SAFE SUBSET of the event: the normalized fields an
// analyst hunts over, but NOT the raw `data` payload or the raw_pointer (those are the most sensitive bits and are
// reached only through the separately role-gated + audited get-raw-event path). Field-level masking (must-add #3)
// blanks a column when the actor's role does not meet that field's MinRole.

import (
	"time"

	"github.com/google/uuid"
)

// maskedText is the placeholder substituted for a field the actor may not see.
const maskedText = "***"

// EventRow is one projected normalized event returned by a hunt query.
type EventRow struct {
	ID         uuid.UUID `json:"id"`
	EventTime  time.Time `json:"event_time"`  // observed_at (source time)
	IngestTime time.Time `json:"ingest_time"` // collected_at
	Source     string    `json:"source"`
	Class      string    `json:"class"`
	Activity   string    `json:"activity"`
	Severity   string    `json:"severity"`
	Confidence int       `json:"confidence"`
	ActorRef   string    `json:"actor_ref"`
	TargetRef  string    `json:"target_ref"`
	Action     string    `json:"action"`
	Outcome    string    `json:"outcome"`
	MITRE      []string  `json:"mitre"`
	Vendor     string    `json:"vendor"`
	Product    string    `json:"product"`
}

// HuntResult is the response of a hunt query: the (masked) rows and the count returned (the same count recorded in the
// read-path audit).
type HuntResult struct {
	Rows  []EventRow `json:"rows"`
	Count int        `json:"count"`
}
