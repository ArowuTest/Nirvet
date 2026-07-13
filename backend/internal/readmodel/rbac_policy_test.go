package readmodel

// Named RBAC policy tests requested by the external auditor. The invariants they check are ALREADY enforced
// structurally (positive-allowlist projections + metadata-by-construction rollups + the fail-closed resolver in
// audience_test.go); these encode the auditor's two exact scenarios as human-readable, behavioural regression
// tests so the intent is unmistakable and a future edit that reopens the hole fails under its own name.
//
//   1. Customer Analyst  --cannot-->  view Internal Analyst Notes
//   2. Government Oversight  --can-->  view Metrics ; --cannot-->  view Evidence

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

// TestPolicy_CustomerAnalystCannotViewInternalAnalystNotes: a customer principal (customer admin/viewer — the
// "customer analyst") resolves to the customer audience, and the customer projection of an incident NEVER
// carries an internal analyst note, whether that note lives in the timeline or in the internal PIR narrative.
func TestPolicy_CustomerAnalystCannotViewInternalAnalystNotes(t *testing.T) {
	// The customer-side roles resolve to the customer audience (not provider).
	for _, r := range []auth.Role{auth.RoleCustomerAdmin, auth.RoleCustomerViewer} {
		if got := Resolve(auth.Principal{Role: r}); got != AudienceCustomer {
			t.Fatalf("role %q must resolve to AudienceCustomer, got %v", r, got)
		}
	}

	const internalNote = "INTERNAL: analyst hypothesis — attacker pivoted via our jump host"
	inc := incident.Incident{
		ID: uuid.New(), Title: "Phishing", Severity: "high", Category: "phishing", Stage: incident.StageContained,
		// Internal PIR narrative (analyst-authored, names internal detail) — withheld by default policy.
		RootCause: internalNote, Impact: "internal impact note", ActionsTaken: "internal actions", LessonsLearned: "internal lessons",
	}
	timeline := []incident.TimelineEntry{
		{At: time.Unix(1, 0), Kind: "note", Visibility: incident.VisibilityInternal, Note: internalNote},
		{At: time.Unix(2, 0), Kind: "status", Visibility: incident.VisibilityCustomer, Note: "We contained the affected host."},
	}

	// Default disclosure policy = withhold the analyst narrative and every internal timeline entry.
	v := ProjectIncidentForCustomer(inc, timeline, DisclosurePolicy{DiscloseClosureNarrative: false})

	// The internal note must appear NOWHERE in the customer view — scan every stringy field defensively.
	if found := containsString(reflect.ValueOf(v), internalNote); found {
		t.Fatalf("customer projection leaked an internal analyst note: %+v", v)
	}
	for _, e := range v.Timeline {
		if e.Note == internalNote {
			t.Fatalf("internal timeline note projected to the customer: %q", e.Note)
		}
	}

	// Structural backstop: the customer-facing timeline entry type must not even have a field that could carry
	// the analyst's identity or an internal-visibility flag (the vector for internal notes leaking).
	tet := reflect.TypeOf(CustomerTimelineEntryView{})
	for i := 0; i < tet.NumField(); i++ {
		name := strings.ToLower(tet.Field(i).Name)
		if strings.Contains(name, "author") || strings.Contains(name, "visibility") || strings.Contains(name, "internal") {
			t.Fatalf("CustomerTimelineEntryView.%s exposes internal analyst metadata to the customer", tet.Field(i).Name)
		}
	}
}

// TestPolicy_GovernmentOversightCanViewMetricsNotEvidence: government/anchor oversight (org-sub-admin, payer)
// resolves to the regulator audience, which CAN see aggregate metrics but CANNOT see incident evidence/content
// — enforced because the entire regulator path is metadata-by-construction (only counts + the low-cardinality
// meta rows), with no field capable of holding a title, note, payload or other evidence.
func TestPolicy_GovernmentOversightCanViewMetricsNotEvidence(t *testing.T) {
	// CAN: the oversight roles resolve to the regulator (metrics) audience.
	for _, r := range []auth.Role{auth.RoleOrgSubAdmin, auth.RolePayer} {
		if got := Resolve(auth.Principal{Role: r}); got != AudienceRegulator {
			t.Fatalf("government-oversight role %q must resolve to AudienceRegulator, got %v", r, got)
		}
	}

	// CAN view metrics: fed metadata, the rollup produces real aggregate counts.
	roll := BuildRegulatorIncidentRollup([]IncidentMeta{
		{Category: "phishing", Severity: "high", Stage: string(incident.StageContained)},
		{Category: "malware", Severity: "critical", Stage: string(incident.StageClosed), ResolveBreached: true},
	}, 2)
	if roll.Total != 2 || roll.ByCategory["phishing"] != 1 || roll.Closed != 1 || roll.ResolveBreached != 1 {
		t.Fatalf("regulator rollup should expose aggregate metrics, got %+v", roll)
	}

	// CANNOT view evidence: neither the rollups NOR the meta rows the regulator path loads have any field that
	// could carry evidence/content (title, note, description, payload, raw event, actor, PII). The rollups are
	// already int/map[string]int by construction; assert the meta rows carry only low-cardinality categoricals.
	evidenceish := []string{"title", "note", "description", "payload", "raw", "event", "evidence", "actor", "body", "detail", "message", "content"}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(RegulatorIncidentRollup{}), reflect.TypeOf(RegulatorAlertRollup{}),
		reflect.TypeOf(IncidentMeta{}), reflect.TypeOf(AlertMeta{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			for _, bad := range evidenceish {
				if strings.Contains(name, bad) {
					t.Errorf("%s.%s could carry evidence/content — the regulator path must stay metadata-only",
						typ.Name(), typ.Field(i).Name)
				}
			}
		}
	}
}

// containsString reports whether any string reachable from v (structs/slices/pointers/maps) contains sub.
func containsString(v reflect.Value, sub string) bool {
	switch v.Kind() {
	case reflect.String:
		return strings.Contains(v.String(), sub)
	case reflect.Ptr, reflect.Interface:
		return !v.IsNil() && containsString(v.Elem(), sub)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if containsString(v.Field(i), sub) {
				return true
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if containsString(v.Index(i), sub) {
				return true
			}
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			if containsString(k, sub) || containsString(v.MapIndex(k), sub) {
				return true
			}
		}
	}
	return false
}
