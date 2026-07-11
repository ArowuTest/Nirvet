package readmodel

import (
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/google/uuid"
)

// DisclosurePolicy is the RESOLVED, tenant-scoped disclosure configuration a projection reads (the DB-backed
// resolution + fail-closed default live in policy.go). It can only WIDEN WITHIN A SAFE ENVELOPE (invariant 6):
// it chooses which customer-SAFE stages/fields appear. It is structurally incapable of exposing a
// provider-internal field, because the projection STRUCTS below physically lack those fields — the policy only
// toggles fields that are already inside the customer-safe envelope.
type DisclosurePolicy struct {
	// CustomerVisibleStages is the row-gate allowlist: a customer sees an incident only once it has reached one
	// of these lifecycle stages (never while in raw internal triage). Fail-closed default in policy.go.
	CustomerVisibleStages map[incident.Stage]bool
	// DiscloseRootCause toggles the one closure field that can name internal detail. Default false (fail-closed);
	// operators opt in per tenant/tier. Everything else in CustomerIncidentView is customer-facing by design.
	DiscloseRootCause bool
}

// IncidentCustomerVisible reports whether an incident is at a stage the policy exposes to the customer audience.
// This is the row-scope gate; a false result means the incident is not returned to a customer at all.
func (p DisclosurePolicy) IncidentCustomerVisible(inc incident.Incident) bool {
	return p.CustomerVisibleStages[inc.Stage]
}

// ---- Customer audience (redacted projection of the tenant's own work-products) ----

// CustomerTimelineEntryView is a customer-facing timeline entry. It names only customer-safe fields — notably
// NOT the internal Author (analyst identity) or the Visibility flag. Only visibility='customer' entries are
// ever projected (ProjectIncidentForCustomer filters defensively, not trusting the caller).
type CustomerTimelineEntryView struct {
	At   time.Time `json:"at"`
	Kind string    `json:"kind"`
	Note string    `json:"note"`
}

// CustomerIncidentView is the positive-allowlist projection of an incident for the customer audience. Every
// field here is deliberately customer-safe; provider-internal fields (OwnerID, the full internal timeline,
// parent/child linkage, detection internals) are ABSENT BY CONSTRUCTION — you cannot leak what the type has no
// field for. RootCause is present but populated only when the disclosure policy opts in.
type CustomerIncidentView struct {
	IncidentID uuid.UUID  `json:"incident_id"`
	Title      string     `json:"title"`
	Severity   string     `json:"severity"`
	Category   string     `json:"category"`
	Status     string     `json:"status"` // the lifecycle stage, customer-facing
	CreatedAt  time.Time  `json:"created_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`

	// SLA adherence — exactly what a customer is entitled to see about service quality.
	AcknowledgedAt  *time.Time `json:"acknowledged_at,omitempty"`
	AckDueAt        *time.Time `json:"ack_due_at,omitempty"`
	ResolveDueAt    *time.Time `json:"resolve_due_at,omitempty"`
	AckBreached     bool       `json:"ack_breached"`
	ResolveBreached bool       `json:"resolve_breached"`

	// Customer-facing closure summary (written for the customer). RootCause is policy-gated.
	Disposition    string `json:"disposition,omitempty"`
	Impact         string `json:"impact,omitempty"`
	ActionsTaken   string `json:"actions_taken,omitempty"`
	LessonsLearned string `json:"lessons_learned,omitempty"`
	RootCause      string `json:"root_cause,omitempty"`
	CustomerAck    bool   `json:"customer_ack"`

	Timeline []CustomerTimelineEntryView `json:"timeline"`
}

// ProjectIncidentForCustomer builds the customer view. It takes the FULL timeline and filters to
// visibility='customer' ITSELF (defense in depth: even if a caller passes the internal timeline by mistake,
// internal notes cannot leak). RootCause is included only when the policy discloses it.
func ProjectIncidentForCustomer(inc incident.Incident, timeline []incident.TimelineEntry, pol DisclosurePolicy) CustomerIncidentView {
	v := CustomerIncidentView{
		IncidentID:      inc.ID,
		Title:           inc.Title,
		Severity:        inc.Severity,
		Category:        inc.Category,
		Status:          string(inc.Stage),
		CreatedAt:       inc.CreatedAt,
		ClosedAt:        inc.ClosedAt,
		AcknowledgedAt:  inc.AcknowledgedAt,
		AckDueAt:        inc.AckDueAt,
		ResolveDueAt:    inc.ResolveDueAt,
		AckBreached:     inc.AckBreached,
		ResolveBreached: inc.ResolveBreached,
		Disposition:     inc.Disposition,
		Impact:          inc.Impact,
		ActionsTaken:    inc.ActionsTaken,
		LessonsLearned:  inc.LessonsLearned,
		CustomerAck:     inc.CustomerAck,
		Timeline:        []CustomerTimelineEntryView{},
	}
	if pol.DiscloseRootCause {
		v.RootCause = inc.RootCause
	}
	for _, e := range timeline {
		if e.Visibility != incident.VisibilityCustomer {
			continue // NEVER project an internal entry to a customer, whatever the caller passed
		}
		v.Timeline = append(v.Timeline, CustomerTimelineEntryView{At: e.At, Kind: e.Kind, Note: e.Note})
	}
	return v
}

// CustomerAlertView is the positive-allowlist projection of an alert for the customer audience: what/how-bad/
// status and the affected asset (the customer's own host). Detection internals (event id, detection/rule id,
// dedupe key, confidence, source connector, MITRE, assignee, the attacker actor_ref) are ABSENT BY CONSTRUCTION.
type CustomerAlertView struct {
	AlertID       uuid.UUID `json:"alert_id"`
	Title         string    `json:"title"`
	Severity      string    `json:"severity"`
	Status        string    `json:"status"`
	AffectedAsset string    `json:"affected_asset,omitempty"` // the customer's own targeted asset (target_ref)
	CreatedAt     time.Time `json:"created_at"`
}

// ProjectAlertForCustomer builds the customer alert view.
func ProjectAlertForCustomer(a alert.Alert) CustomerAlertView {
	return CustomerAlertView{
		AlertID:       a.ID,
		Title:         a.Title,
		Severity:      a.Severity,
		Status:        string(a.Status),
		AffectedAsset: a.TargetRef,
		CreatedAt:     a.CreatedAt,
	}
}

// ---- Regulator audience (metadata-by-construction AGGREGATES; grant-scoped; NEVER content rows) ----

// RegulatorIncidentRollup is the government/anchor oversight view of incidents across a grant-scoped set of
// tenants. It is metadata-BY-CONSTRUCTION: there is NO field on this struct (or its maps' keys) that can hold
// incident content, a title, or PII — only counts keyed by low-cardinality categorical labels + SLA tallies.
// The regulator therefore physically cannot receive incident content, whatever the query returns.
type RegulatorIncidentRollup struct {
	TenantsInScope  int            `json:"tenants_in_scope"`
	Total           int            `json:"total"`
	Open            int            `json:"open"`
	Closed          int            `json:"closed"`
	ByCategory      map[string]int `json:"by_category"`
	BySeverity      map[string]int `json:"by_severity"`
	AckBreached     int            `json:"ack_breached"`
	ResolveBreached int            `json:"resolve_breached"`
}

// BuildRegulatorIncidentRollup aggregates incidents (already fetched over the grant-scoped tenant set) into
// counts. It reads only categorical/boolean fields; it never copies Title, notes, or any content into the
// result. tenantsInScope is the size of the resolved grant scope (0 → an empty, fail-closed rollup).
func BuildRegulatorIncidentRollup(incidents []incident.Incident, tenantsInScope int) RegulatorIncidentRollup {
	r := RegulatorIncidentRollup{
		TenantsInScope: tenantsInScope,
		ByCategory:     map[string]int{},
		BySeverity:     map[string]int{},
	}
	for _, inc := range incidents {
		r.Total++
		r.ByCategory[inc.Category]++
		r.BySeverity[inc.Severity]++
		if inc.Stage == incident.StageClosed || inc.Stage == incident.StagePostIncidentReview {
			r.Closed++
		} else {
			r.Open++
		}
		if inc.AckBreached {
			r.AckBreached++
		}
		if inc.ResolveBreached {
			r.ResolveBreached++
		}
	}
	return r
}

// RegulatorAlertRollup is the metadata-by-construction alert aggregate for the regulator audience.
type RegulatorAlertRollup struct {
	TenantsInScope int            `json:"tenants_in_scope"`
	Total          int            `json:"total"`
	BySeverity     map[string]int `json:"by_severity"`
	ByStatus       map[string]int `json:"by_status"`
}

// BuildRegulatorAlertRollup aggregates alerts into counts only.
func BuildRegulatorAlertRollup(alerts []alert.Alert, tenantsInScope int) RegulatorAlertRollup {
	r := RegulatorAlertRollup{
		TenantsInScope: tenantsInScope,
		BySeverity:     map[string]int{},
		ByStatus:       map[string]int{},
	}
	for _, a := range alerts {
		r.Total++
		r.BySeverity[a.Severity]++
		r.ByStatus[string(a.Status)]++
	}
	return r
}
