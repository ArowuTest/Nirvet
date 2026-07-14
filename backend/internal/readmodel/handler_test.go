package readmodel

// Adversarial read-matrix (reviewer invariant 3): call each customer-reachable endpoint as each principal and
// assert no over-disclosure. Handler-level test (no full HTTP stack): deps are fakes, the principal is injected
// into the request context exactly as the auth middleware would. Covers the audience gate + the row-stage gate +
// field-level redaction + regulator metadata-only scoping.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

// ---- fakes ----

type fakeInc struct {
	get  *incident.Incident
	tl   []incident.TimelineEntry
	list []incident.Incident
}

func (f fakeInc) Get(_ context.Context, _, _ uuid.UUID) (*incident.Incident, error) {
	return f.get, nil
}
func (f fakeInc) Timeline(_ context.Context, _, _ uuid.UUID) ([]incident.TimelineEntry, error) {
	return f.tl, nil
}
func (f fakeInc) List(_ context.Context, _ uuid.UUID) ([]incident.Incident, error) {
	return f.list, nil
}

type fakeAlerts struct{ list []alert.Alert }

func (f fakeAlerts) List(_ context.Context, _ uuid.UUID, _ string) ([]alert.Alert, error) {
	return f.list, nil
}

type fakePolicy struct{ pol DisclosurePolicy }

func (f fakePolicy) Resolve(_ context.Context, _ uuid.UUID) (DisclosurePolicy, error) {
	return f.pol, nil
}
func (f fakePolicy) SetPolicy(context.Context, auth.Principal, uuid.UUID, []string, bool) error {
	return nil
}

type fakeReg struct {
	inc []IncidentMeta
	al  []AlertMeta
}

// Mirrors the SD function's fail-closed empty-scope behavior.
func (f fakeReg) IncidentMetaForTenants(_ context.Context, ids []uuid.UUID) ([]IncidentMeta, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return f.inc, nil
}
func (f fakeReg) AlertMetaForTenants(_ context.Context, ids []uuid.UUID) ([]AlertMeta, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return f.al, nil
}

type fakeScope struct{ ids []uuid.UUID }

func (f fakeScope) TenantScope(context.Context, auth.Principal) ([]uuid.UUID, error) {
	return f.ids, nil
}

func newHandler(inc IncidentReader, al AlertReader, pol PolicyAPI, reg RegulatorMetaReader, scope ScopeResolver) *Handler {
	// nil db → oversight read-audit is a no-op in tests; nil asset/vuln/compliance readers → Slice B handlers
	// return empty lists (these Slice A tests don't exercise them; Slice B has its own handler tests).
	return NewHandler(inc, al, pol, reg, scope, nil, nil, nil, nil, nil, nil)
}

func call(h func(http.ResponseWriter, *http.Request), p auth.Principal, pathID string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r = r.WithContext(auth.WithPrincipal(r.Context(), p))
	if pathID != "" {
		r.SetPathValue("id", pathID)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

var (
	custViewer = auth.Principal{Role: auth.RoleCustomerViewer, TenantID: uuid.New(), UserID: uuid.New()}
	provider   = auth.Principal{Role: auth.RolePlatformAdmin, TenantID: uuid.New(), UserID: uuid.New()}
	regulator  = auth.Principal{Role: auth.RoleOrgSubAdmin, TenantID: uuid.New(), UserID: uuid.New()}
)

// inv.2 + inv.3: wrong audience is refused at the handler, on top of the route gate.
func TestAudienceGate_Refusals(t *testing.T) {
	h := newHandler(fakeInc{}, fakeAlerts{}, fakePolicy{DefaultDisclosurePolicy()}, fakeReg{}, fakeScope{})
	// A provider must not reach the CUSTOMER endpoints (those are redacted views for customers, not the SOC).
	if w := call(h.ListIncidents, provider, ""); w.Code != http.StatusForbidden {
		t.Errorf("provider on customer ListIncidents: got %d, want 403", w.Code)
	}
	if w := call(h.ListAlerts, provider, ""); w.Code != http.StatusForbidden {
		t.Errorf("provider on customer ListAlerts: got %d, want 403", w.Code)
	}
	// A customer must not reach the REGULATOR rollups.
	if w := call(h.IncidentRollup, custViewer, ""); w.Code != http.StatusForbidden {
		t.Errorf("customer on regulator IncidentRollup: got %d, want 403", w.Code)
	}
	// A regulator must not reach the CUSTOMER endpoints.
	if w := call(h.GetIncident, regulator, uuid.NewString()); w.Code != http.StatusForbidden {
		t.Errorf("regulator on customer GetIncident: got %d, want 403", w.Code)
	}
}

// inv.3: a customer sees a customer-visible incident redacted — internal timeline + root cause never leak.
func TestCustomerGetIncident_RedactsInternal(t *testing.T) {
	inc := &incident.Incident{
		ID: uuid.New(), Title: "Phishing", Severity: "high", Category: "phishing",
		Stage: incident.StageContained,
		// All four free-text closure fields carry internal detail (RM-1).
		RootCause: "pivoted via internal jump host", Impact: "SECRET-impact-detail",
		ActionsTaken: "SECRET-actions-vendorX", LessonsLearned: "SECRET-our-rule-gap",
	}
	tl := []incident.TimelineEntry{
		{Kind: "note", Visibility: incident.VisibilityInternal, Note: "SECRET-internal-hypothesis", At: time.Unix(1, 0)},
		{Kind: "status", Visibility: incident.VisibilityCustomer, Note: "Host contained.", At: time.Unix(2, 0)},
	}
	h := newHandler(fakeInc{get: inc, tl: tl}, fakeAlerts{}, fakePolicy{DefaultDisclosurePolicy()}, fakeReg{}, fakeScope{})

	w := call(h.GetIncident, custViewer, inc.ID.String())
	if w.Code != http.StatusOK {
		t.Fatalf("GetIncident: got %d, want 200", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "SECRET-internal-hypothesis") {
		t.Fatal("internal timeline note leaked to customer")
	}
	// RM-1: none of the four free-text closure/PIR fields may leak under the default (narrative-withheld) policy.
	for _, secret := range []string{"pivoted via internal jump host", "SECRET-impact-detail", "SECRET-actions-vendorX", "SECRET-our-rule-gap"} {
		if strings.Contains(body, secret) {
			t.Fatalf("closure narrative %q leaked to customer under the default (non-disclosing) policy", secret)
		}
	}
	for _, forbidden := range []string{"owner_id", "tenant_id", "parent_id"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("internal field %q present in customer incident view", forbidden)
		}
	}
}

// inv.3 (row gate): an incident at an internal-only stage is 404 to a customer — existence is not revealed.
func TestCustomerGetIncident_InternalStageHidden(t *testing.T) {
	inc := &incident.Incident{ID: uuid.New(), Title: "Early triage", Stage: incident.StageTriage}
	h := newHandler(fakeInc{get: inc}, fakeAlerts{}, fakePolicy{DefaultDisclosurePolicy()}, fakeReg{}, fakeScope{})
	if w := call(h.GetIncident, custViewer, inc.ID.String()); w.Code != http.StatusNotFound {
		t.Fatalf("internal-stage incident to customer: got %d, want 404", w.Code)
	}
}

// inv.3: customer alert view carries no detection internals.
func TestCustomerListAlerts_NoDetectionInternals(t *testing.T) {
	det := uuid.New()
	als := []alert.Alert{{
		ID: uuid.New(), Title: "Suspicious login", Severity: "medium", Status: alert.StatusNew,
		DetectionID: &det, ActorRef: "1.2.3.4", TargetRef: "host:FIN-01", Confidence: 87, DedupeKey: "ev:rule",
	}}
	h := newHandler(fakeInc{}, fakeAlerts{list: als}, fakePolicy{DefaultDisclosurePolicy()}, fakeReg{}, fakeScope{})
	w := call(h.ListAlerts, custViewer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("ListAlerts: got %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, forbidden := range []string{"detection_id", "actor_ref", "confidence", "dedupe_key", "1.2.3.4"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("customer alert view leaked %q: %s", forbidden, body)
		}
	}
	if !strings.Contains(body, "host:FIN-01") { // the customer's OWN affected asset is allowed
		t.Error("expected affected_asset (customer's own host) in the view")
	}
}

// inv.5 (end-to-end): the regulator rollup is metadata-only and grant-scoped; an empty scope yields zeros.
func TestRegulatorRollup_MetadataOnlyAndScoped(t *testing.T) {
	reg := fakeReg{inc: []IncidentMeta{
		{Category: "phishing", Severity: "high", Stage: string(incident.StageContained), AckBreached: true},
		{Category: "malware", Severity: "critical", Stage: string(incident.StageClosed)},
	}}
	// With scope → aggregated counts, no content.
	h := newHandler(fakeInc{}, fakeAlerts{}, fakePolicy{}, reg, fakeScope{ids: []uuid.UUID{uuid.New()}})
	w := call(h.IncidentRollup, regulator, "")
	if w.Code != http.StatusOK {
		t.Fatalf("IncidentRollup: got %d, want 200", w.Code)
	}
	var roll RegulatorIncidentRollup
	if err := json.Unmarshal(w.Body.Bytes(), &roll); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if roll.Total != 2 || roll.Open != 1 || roll.Closed != 1 || roll.AckBreached != 1 {
		t.Fatalf("unexpected rollup: %+v", roll)
	}
	if strings.Contains(w.Body.String(), "phishing") == false {
		t.Error("expected category counts") // category label is metadata, allowed
	}

	// Empty scope (no grant) → fail-closed zeros.
	h2 := newHandler(fakeInc{}, fakeAlerts{}, fakePolicy{}, reg, fakeScope{ids: nil})
	w2 := call(h2.IncidentRollup, regulator, "")
	var roll2 RegulatorIncidentRollup
	_ = json.Unmarshal(w2.Body.Bytes(), &roll2)
	if roll2.Total != 0 || roll2.TenantsInScope != 0 {
		t.Fatalf("empty scope must yield zero rollup, got %+v", roll2)
	}
}
