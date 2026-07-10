package investigation

// §6.9 #124 I-4 — the structured investigation timeline (INV-002). The existing incident timeline is a flat journal
// (one timestamp + free-text note); this adds the forensic EVENT lane the SRS asks for: event-time vs ingest-time,
// source, entity, action, severity, confidence, outcome — a real multi-field chronology. It composes the I-1 hunt
// engine with a FIXED actor-OR-target predicate (so it inherits the allow-list/RLS/cost/audit guarantees for free),
// then projects the rows into typed timeline entries. Analyst/automation/customer-comms/evidence lanes already live
// in the incident journal (incident.Timeline); this is the additive event lane keyed on an entity.

import (
	"context"
	"sort"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
)

// TimelineEntry is one forensic event on the timeline (INV-002 field set).
type TimelineEntry struct {
	EventTime  time.Time `json:"event_time"`  // observed_at (source time)
	IngestTime time.Time `json:"ingest_time"` // collected_at
	Source     string    `json:"source"`
	Entity     string    `json:"entity"`
	Action     string    `json:"action"`
	Severity   string    `json:"severity"`
	Confidence int       `json:"confidence"`
	Outcome    string    `json:"outcome"`
	Lane       string    `json:"lane"` // "event" (analyst/automation/comms/evidence lanes are the incident journal)
}

// Timeline is the entity's forensic event timeline.
type Timeline struct {
	Entity  Entity          `json:"entity"`
	Entries []TimelineEntry `json:"entries"`
}

// GetTimeline builds the forensic event timeline for an entity over a bounded window. It runs as a hunt query
// (actor_ref = ref OR target_ref = ref) so the whole security envelope applies, then returns the rows in ascending
// chronological order and records the read-path audit.
func (s *Service) GetTimeline(ctx context.Context, p auth.Principal, ref string, from, to time.Time) (Timeline, error) {
	e, err := ParseEntity(ref)
	if err != nil {
		return Timeline{}, err
	}
	lim := s.repo.LoadLimits(ctx)
	q := HuntQuery{From: from, To: to, Any: []Predicate{
		{Field: "actor_ref", Op: OpEq, Value: e.Ref()},
		{Field: "target_ref", Op: OpEq, Value: e.Ref()},
	}}
	if err := q.Validate(p, lim); err != nil {
		return Timeline{}, err
	}
	rows, err := s.repo.RunHunt(ctx, p.TenantID, Compile(q), q.Limit)
	if err != nil {
		return Timeline{}, err
	}
	tl := Timeline{Entity: e}
	for _, r := range rows {
		tl.Entries = append(tl.Entries, TimelineEntry{
			EventTime: r.EventTime, IngestTime: r.IngestTime, Source: r.Source, Entity: e.Ref(),
			Action: r.Action, Severity: r.Severity, Confidence: r.Confidence, Outcome: r.Outcome, Lane: "event",
		})
	}
	sort.Slice(tl.Entries, func(i, j int) bool { return tl.Entries[i].EventTime.Before(tl.Entries[j].EventTime) })
	if err := s.repo.WriteQueryAudit(ctx, p.TenantID, p.UserID, "entity_read",
		map[string]string{"ref": e.Ref(), "op": "timeline"}, len(rows)); err != nil {
		return Timeline{}, err
	}
	return tl, nil
}
