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

// inv.1 (RM-2): the customer projections are POSITIVE allowlists — assert the EXACT field set. Any field added
// to (or removed from) a projection fails the build until it is DELIBERATELY reviewed and added to the expected
// list. A name-denylist (the previous version) fails OPEN: a newly-added internal field would sail through. This
// mirrors the type-allowlist guard on the regulator rollups below.
func TestCustomerProjections_ExactAllowlist(t *testing.T) {
	if reflect.TypeOf(CustomerIncidentView{}) == reflect.TypeOf(incident.Incident{}) {
		t.Fatal("CustomerIncidentView must be a distinct type, not the incident entity")
	}
	if reflect.TypeOf(CustomerAlertView{}) == reflect.TypeOf(alert.Alert{}) {
		t.Fatal("CustomerAlertView must be a distinct type, not the alert entity")
	}
	assertExactFields(t, reflect.TypeOf(CustomerIncidentView{}), []string{
		"IncidentID", "Title", "Severity", "Category", "Status", "CreatedAt", "ClosedAt",
		"AcknowledgedAt", "AckDueAt", "ResolveDueAt", "AckBreached", "ResolveBreached",
		"Disposition", "Impact", "ActionsTaken", "LessonsLearned", "RootCause", "CustomerAck", "Timeline",
	})
	assertExactFields(t, reflect.TypeOf(CustomerAlertView{}), []string{
		"AlertID", "Title", "Severity", "Status", "AffectedAsset", "CreatedAt",
	})
	// Slice B customer views — same allowlist discipline: name ONLY customer-safe fields. If someone adds an
	// internal field to one of these structs (or projects the raw entity), this test fails before it can ship.
	assertExactFields(t, reflect.TypeOf(CustomerAssetView{}), []string{
		"AssetID", "Ref", "Name", "Kind", "Criticality", "CreatedAt",
	})
	// Asset detail embeds the asset view + its blast radius (each a customer *View, no raw entity).
	assertExactFields(t, reflect.TypeOf(CustomerAssetDetailView{}), []string{
		"CustomerAssetView", "Vulnerabilities", "Alerts",
	})
	assertExactFields(t, reflect.TypeOf(CustomerVulnerabilityView{}), []string{
		"Ref", "CVE", "Title", "Severity", "CVSS", "Exploited", "Status", "RemediationDue", "CreatedAt",
	})
	assertExactFields(t, reflect.TypeOf(CustomerComplianceView{}), []string{
		"Key", "Name", "Version", "Score", "Summary",
	})
	// Compliance drill-down: per-control status/description is customer-safe; the internal ControlAssessment
	// fields (source/note/evidence) must never appear on these projections.
	assertExactFields(t, reflect.TypeOf(CustomerComplianceControlView{}), []string{
		"ControlRef", "Title", "Description", "Status",
	})
	assertExactFields(t, reflect.TypeOf(CustomerComplianceFunctionView{}), []string{
		"ControlRef", "Title", "Description", "Status", "Controls",
	})
	assertExactFields(t, reflect.TypeOf(CustomerComplianceDetailView{}), []string{
		"Key", "Name", "Version", "Score", "Summary", "Functions",
	})
	// Risk score is an aggregate about the customer's OWN estate — composite + band + per-component risk.
	assertExactFields(t, reflect.TypeOf(CustomerRiskScoreView{}), []string{
		"Composite", "Band", "Tone", "Components",
	})
}

// assertExactFields fails unless the struct's field names are EXACTLY `want` — no more, no fewer.
func assertExactFields(t *testing.T, typ reflect.Type, want []string) {
	t.Helper()
	got := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		got[typ.Field(i).Name] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("%s: expected allowlisted field %q is missing", typ.Name(), w)
		}
		delete(got, w)
	}
	for extra := range got {
		t.Errorf("%s: UNEXPECTED field %q — a new projection field must be added to the allowlist DELIBERATELY "+
			"(confirm it is customer-safe), never appear implicitly", typ.Name(), extra)
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

func TestProjectIncidentForCustomer_DropsInternalAndGatesNarrative(t *testing.T) {
	inc := incident.Incident{
		ID: uuid.New(), Title: "Phishing", Severity: "high", Category: "phishing",
		Stage: incident.StageContained, Disposition: "true_positive",
		// RM-1: all four are free-text CASE-009 closure fields (the internal PIR) — must be gated together.
		RootCause: "analyst pivoted via internal jump host", Impact: "3 mailboxes exposed",
		ActionsTaken: "isolated via Defender; our rule R missed this", LessonsLearned: "tune rule R coverage",
	}
	full := []incident.TimelineEntry{
		{At: time.Unix(1, 0), Kind: "note", Visibility: incident.VisibilityInternal, Note: "SECRET internal hypothesis"},
		{At: time.Unix(2, 0), Kind: "status", Visibility: incident.VisibilityCustomer, Note: "We contained the affected host."},
	}

	// Policy WITHHOLDING the closure narrative (default): all four free-text fields blank; internal timeline dropped.
	v := ProjectIncidentForCustomer(inc, full, DisclosurePolicy{DiscloseClosureNarrative: false})
	if len(v.Timeline) != 1 || v.Timeline[0].Note != "We contained the affected host." {
		t.Fatalf("internal timeline entry leaked or customer entry missing: %+v", v.Timeline)
	}
	if v.RootCause != "" || v.Impact != "" || v.ActionsTaken != "" || v.LessonsLearned != "" {
		t.Fatalf("closure narrative must be blank when policy withholds it: root=%q impact=%q actions=%q lessons=%q",
			v.RootCause, v.Impact, v.ActionsTaken, v.LessonsLearned)
	}
	if v.Disposition != "true_positive" { // bounded enum — customer-safe, unconditional
		t.Fatalf("Disposition (bounded enum) must stay unconditional, got %q", v.Disposition)
	}

	// Policy DISCLOSING the narrative (operator opt-in, still inside the safe envelope): all four appear.
	v2 := ProjectIncidentForCustomer(inc, full, DisclosurePolicy{DiscloseClosureNarrative: true})
	if v2.RootCause != inc.RootCause || v2.Impact != inc.Impact || v2.ActionsTaken != inc.ActionsTaken || v2.LessonsLearned != inc.LessonsLearned {
		t.Fatalf("closure narrative should be disclosed when policy opts in: %+v", v2)
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
