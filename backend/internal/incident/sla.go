package incident

import (
	"strings"
	"time"
)

// SLA targets per severity (SRS §6.8). ack = time-to-acknowledge (first ownership),
// resolve = time-to-resolve (close). Policy lives in code so it is documented and
// unit-testable; due-times are stamped onto the incident at creation.
type slaTarget struct{ ack, resolve time.Duration }

var slaTargets = map[string]slaTarget{
	"critical":      {15 * time.Minute, 4 * time.Hour},
	"high":          {30 * time.Minute, 8 * time.Hour},
	"medium":        {2 * time.Hour, 24 * time.Hour},
	"low":           {8 * time.Hour, 72 * time.Hour},
	"informational": {24 * time.Hour, 120 * time.Hour},
}

// slaFor returns the ack/resolve targets for a severity, defaulting to 'medium' for
// an unknown/blank severity (never leave a case without an SLA).
func slaFor(severity string) slaTarget {
	if t, ok := slaTargets[strings.ToLower(strings.TrimSpace(severity))]; ok {
		return t
	}
	return slaTargets["medium"]
}

// dueTimes computes the acknowledge + resolve deadlines from a start time.
func (t slaTarget) dueTimes(from time.Time) (ackDue, resolveDue time.Time) {
	return from.Add(t.ack), from.Add(t.resolve)
}

// computeBreach fills the derived SLA-breach flags for an incident, given the current
// time. Ack is breached if it was acknowledged after its deadline, or is still
// unacknowledged past due. Resolve is breached if it was closed late, or is still open
// past due. Incidents with no due-times (pre-SLA rows) are never breached.
func computeBreach(i *Incident, now time.Time) {
	if i.AckDueAt != nil {
		if i.AcknowledgedAt != nil {
			i.AckBreached = i.AcknowledgedAt.After(*i.AckDueAt)
		} else {
			i.AckBreached = now.After(*i.AckDueAt)
		}
	}
	if i.ResolveDueAt != nil {
		if i.ClosedAt != nil {
			i.ResolveBreached = i.ClosedAt.After(*i.ResolveDueAt)
		} else {
			i.ResolveBreached = now.After(*i.ResolveDueAt)
		}
	}
}
