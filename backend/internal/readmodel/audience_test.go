package readmodel

// Pure unit tests (no DB) for the customer read-side layer. These encode the reviewer's hard invariants as
// executable checks so a future edit that would break them fails the build:
//   - inv.1 positive-allowlist projections (distinct types; no internal field names leak in),
//   - inv.5 metadata-by-construction regulator rollups (structurally no content field),
//   - resolver classification (fail-closed to AudienceNone),
//   - projection correctness (internal timeline entries never projected; RootCause policy-gated; stage gate).

import (
	"reflect"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

func TestResolve_Classification(t *testing.T) {
	cases := []struct {
		role auth.Role
		want Audience
	}{
		{auth.RolePlatformAdmin, AudienceProvider},
		{auth.RoleSOCManager, AudienceProvider},
		{auth.RoleAnalystT1, AudienceProvider},
		{auth.RoleDetectionEng, AudienceProvider},
		{auth.RoleCustomerAdmin, AudienceCustomer},
		{auth.RoleCustomerViewer, AudienceCustomer},
		{auth.RoleOrgSubAdmin, AudienceRegulator},
		{auth.RolePayer, AudienceRegulator},
		{auth.Role("some_future_role"), AudienceNone}, // fail-closed: unknown role gets NO view
		{auth.Role(""), AudienceNone},
	}
	for _, c := range cases {
		if got := Resolve(auth.Principal{Role: c.role}); got != c.want {
			t.Errorf("Resolve(%q) = %v, want %v", c.role, got, c.want)
		}
	}
}

// inv.1: projections are distinct types, and NO provider-internal field name appears in a customer projection.
// A denylist would fail open when the entity grows; this asserts the allowlist stays an allowlist.
func TestProjections_AreAllowlists(t *testing.T) {
	if reflect.TypeOf(CustomerIncidentView{}) == reflect.TypeOf(incident.Incident{}) {
		t.Fatal("CustomerIncidentView must be a distinct type, not the incident entity")
	}
	if reflect.TypeOf(CustomerAlertView{}) == reflect.TypeOf(alert.Alert{}) {
		t.Fatal("CustomerAlertView must be a distinct type, not the alert entity")
	}

	forbiddenIncident := map[string]bool{"TenantID": true, "OwnerID": true, "ParentID": true, "IsMajor": true}
	assertNoFields(t, reflect.TypeOf(CustomerIncidentView{}), forbiddenIncident)

	// Detection internals + attacker actor must be absent from the customer alert view by construction.
	forbiddenAlert := map[string]bool{
		"TenantID": true, "EventID": true, "DetectionID": true, "DedupeKey": true,
		"Confidence": true, "Source": true, "AssigneeID": true, "ActorRef": true, "MITRE": true, "IncidentID": true,
	}
	assertNoFields(t, reflect.TypeOf(CustomerAlertView{}), forbiddenAlert)
}

func assertNoFields(t *testing.T, typ reflect.Type, forbidden map[string]bool) {
	t.Helper()
	for i := 0; i < typ.NumField(); i++ {
		if forbidden[typ.Field(i).Name] {
			t.Errorf("%s must not expose internal field %q", typ.Name(), typ.Field(i).Name)
		}
	}
}

// inv.5: a regulator rollup is metadata-BY-CONSTRUCTION — every field is a count (int) or a categorical
// count map (map[string]int). No string/free-text/struct/slice field can exist to carry content or PII.
func TestRegulatorRollups_AreMetadataByConstruction(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(RegulatorIncidentRollup{}),
		reflect.TypeOf(RegulatorAlertRollup{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			switch f.Type.Kind() {
			case reflect.Int:
				// a count — fine
			case reflect.Map:
				if f.Type.Key().Kind() != reflect.String || f.Type.Elem().Kind() != reflect.Int {
					t.Errorf("%s.%s must be map[string]int (categorical counts), got %s", typ.Name(), f.Name, f.Type)
				}
			default:
				t.Errorf("%s.%s is %s — a regulator rollup may carry only int counts and map[string]int, never a content-capable field", typ.Name(), f.Name, f.Type)
			}
		}
	}
}

func TestProjectIncidentForCustomer_DropsInternalAndGatesRootCause(t *testing.T) {
	inc := incident.Incident{
		ID: uuid.New(), Title: "Phishing", Severity: "high", Category: "phishing",
		Stage: incident.StageContained, RootCause: "analyst pivoted via internal jump host",
	}
	full := []incident.TimelineEntry{
		{At: time.Unix(1, 0), Kind: "note", Visibility: incident.VisibilityInternal, Note: "SECRET internal hypothesis"},
		{At: time.Unix(2, 0), Kind: "status", Visibility: incident.VisibilityCustomer, Note: "We contained the affected host."},
	}

	// Policy WITHOUT root-cause disclosure.
	v := ProjectIncidentForCustomer(inc, full, DisclosurePolicy{DiscloseRootCause: false})
	if len(v.Timeline) != 1 || v.Timeline[0].Note != "We contained the affected host." {
		t.Fatalf("internal timeline entry leaked or customer entry missing: %+v", v.Timeline)
	}
	if v.RootCause != "" {
		t.Fatalf("RootCause must be blank when policy does not disclose it, got %q", v.RootCause)
	}

	// Policy WITH root-cause disclosure (still inside the safe envelope).
	v2 := ProjectIncidentForCustomer(inc, full, DisclosurePolicy{DiscloseRootCause: true})
	if v2.RootCause != inc.RootCause {
		t.Fatalf("RootCause should be disclosed when policy opts in")
	}
}

func TestDisclosurePolicy_StageGate(t *testing.T) {
	pol := DisclosurePolicy{CustomerVisibleStages: map[incident.Stage]bool{incident.StageContained: true, incident.StageClosed: true}}
	if !pol.IncidentCustomerVisible(incident.Incident{Stage: incident.StageContained}) {
		t.Error("contained incident should be customer-visible under this policy")
	}
	if pol.IncidentCustomerVisible(incident.Incident{Stage: incident.StageTriage}) {
		t.Error("triage incident must NOT be customer-visible (internal stage)")
	}
}
