package investigation

// #188 LAUNCH #5 (MEDIUM) — multi-lane CASE timeline. The single-entity GetTimeline (I-4) is the forensic EVENT
// lane; the analyst/automation/comms/evidence lanes live in the incident journal (incident.Timeline). This merges
// both into ONE chronological, lane-tagged view for a case — the standard SOC "case timeline". The EVENT lane
// reuses GetTimeline (so it inherits the I-1 allow-list / RLS / cost / audit envelope for free); the journal lanes
// come from the incident journal (tenant-scoped via RLS). Investigation stays decoupled from incident via the
// narrow CaseJournalReader interface (implemented by an adapter over incident.Service in main).

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// CaseJournalEntry is one incident-journal entry the case timeline merges (mapped from incident.TimelineEntry).
type CaseJournalEntry struct {
	At         time.Time
	Author     string
	Kind       string // note|status|action|evidence
	Visibility string // internal|customer
	Note       string
}

// CaseJournalReader returns an incident's journal. Implemented by an adapter over incident.Service; nil ⇒ the case
// timeline has only the forensic event lane (investigation stays usable without the incident dependency).
type CaseJournalReader interface {
	CaseJournal(ctx context.Context, tenantID, incidentID uuid.UUID) ([]CaseJournalEntry, error)
}

// WithCaseJournal wires the incident-journal reader (chainable).
func (s *Service) WithCaseJournal(r CaseJournalReader) *Service { s.journal = r; return s }

// CaseTimelineEntry is one lane-tagged entry on the merged case timeline.
type CaseTimelineEntry struct {
	At       time.Time `json:"at"`
	Lane     string    `json:"lane"` // event|analyst|automation|comms|evidence
	Source   string    `json:"source,omitempty"`
	Entity   string    `json:"entity,omitempty"`
	Actor    string    `json:"actor,omitempty"`
	Summary  string    `json:"summary"`
	Severity string    `json:"severity,omitempty"`
	Outcome  string    `json:"outcome,omitempty"`
}

// CaseTimeline is the merged, chronological, lane-tagged timeline for one case.
type CaseTimeline struct {
	IncidentID uuid.UUID           `json:"incident_id"`
	Entries    []CaseTimelineEntry `json:"entries"`
}

// maxCaseTimelineRefs bounds how many entities the event lane hunts over per request (each ref is a hunt query).
const maxCaseTimelineRefs = 10

// GetCaseTimeline merges the forensic event lane (a hunt per ref) with the incident-journal lanes into one
// chronological timeline over a bounded window. refs is optional (empty ⇒ journal lanes only). Provider-gated at
// the route, same as GetTimeline.
func (s *Service) GetCaseTimeline(ctx context.Context, p auth.Principal, incidentID uuid.UUID, refs []string, from, to time.Time) (CaseTimeline, error) {
	if len(refs) > maxCaseTimelineRefs {
		return CaseTimeline{}, httpx.ErrBadRequest("too many refs on a case timeline (max 10)")
	}
	out := CaseTimeline{IncidentID: incidentID}

	// EVENT lane — reuse GetTimeline per ref (inherits allow-list/RLS/cost/audit).
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		tl, err := s.GetTimeline(ctx, p, ref, from, to)
		if err != nil {
			return CaseTimeline{}, err
		}
		for _, e := range tl.Entries {
			out.Entries = append(out.Entries, CaseTimelineEntry{
				At: e.EventTime, Lane: "event", Source: e.Source, Entity: e.Entity,
				Summary: e.Action, Severity: e.Severity, Outcome: e.Outcome,
			})
		}
	}

	// JOURNAL lanes — analyst/automation/comms/evidence, filtered to the same bounded window as the event lane.
	if s.journal != nil {
		js, err := s.journal.CaseJournal(ctx, p.TenantID, incidentID)
		if err != nil {
			return CaseTimeline{}, err
		}
		for _, j := range js {
			if j.At.Before(from) || j.At.After(to) {
				continue
			}
			out.Entries = append(out.Entries, CaseTimelineEntry{
				At: j.At, Lane: journalLane(j), Actor: j.Author, Summary: j.Note,
			})
		}
	}

	sort.Slice(out.Entries, func(i, k int) bool { return out.Entries[i].At.Before(out.Entries[k].At) })

	// Read-path audit for the case-timeline read (kind=entity_read — the case timeline is a merged entity-timeline
	// read; op distinguishes it. Each per-entity read is additionally audited by GetTimeline).
	if err := s.repo.WriteQueryAudit(ctx, p.TenantID, p.UserID, "entity_read",
		map[string]string{"incident": incidentID.String(), "op": "case_timeline"}, len(out.Entries)); err != nil {
		return CaseTimeline{}, err
	}
	return out, nil
}

// journalLane maps an incident-journal entry to its timeline lane. A customer-visible entry is a comms-lane item
// regardless of kind; otherwise the kind selects the lane (evidence, automation for actions, analyst otherwise).
func journalLane(j CaseJournalEntry) string {
	if j.Visibility == "customer" {
		return "comms"
	}
	switch j.Kind {
	case "evidence":
		return "evidence"
	case "action":
		return "automation"
	default: // note | status
		return "analyst"
	}
}
