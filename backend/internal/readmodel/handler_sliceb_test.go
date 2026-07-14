package readmodel

// Slice B adversarial read-matrix: the customer asset/vuln/compliance endpoints must (1) refuse a non-customer
// audience and (2) project ONLY customer-safe fields — internal asset owner/tags never reach the customer.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/compliance"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/vulnerability"
	"github.com/google/uuid"
)

// reqWithKey drives a handler with the {key} path value set (the framework detail route), mirroring `call`.
func reqWithKey(h func(http.ResponseWriter, *http.Request), p auth.Principal, key string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r = r.WithContext(auth.WithPrincipal(r.Context(), p))
	r.SetPathValue("key", key)
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

type fakeAssets struct {
	list []asset.Asset
	get  *asset.Asset
}

func (f fakeAssets) List(_ context.Context, _ uuid.UUID) ([]asset.Asset, error) { return f.list, nil }
func (f fakeAssets) Get(_ context.Context, _, _ uuid.UUID) (*asset.Asset, error) {
	if f.get == nil {
		return nil, httpx.ErrNotFound("asset not found")
	}
	return f.get, nil
}

type fakeVulns struct {
	list   []vulnerability.Vuln
	byRefs []vulnerability.Vuln
}

func (f fakeVulns) List(_ context.Context, _ uuid.UUID, _, _ string) ([]vulnerability.Vuln, error) {
	return f.list, nil
}
func (f fakeVulns) FindOpenByRefs(_ context.Context, _ uuid.UUID, _ []string) ([]vulnerability.Vuln, error) {
	return f.byRefs, nil
}

type fakeCompliance struct {
	fws []compliance.Framework
	cov *compliance.Coverage
}

func (f fakeCompliance) ListFrameworks(_ context.Context, _ uuid.UUID) ([]compliance.Framework, error) {
	return f.fws, nil
}
func (f fakeCompliance) Assess(_ context.Context, _ uuid.UUID, _ string) (*compliance.Coverage, error) {
	return f.cov, nil
}
func (f fakeCompliance) ListControls(_ context.Context, _ uuid.UUID, _ string) ([]compliance.Control, error) {
	return nil, nil
}

func sliceBHandler() *Handler {
	assets := []asset.Asset{{
		ID: uuid.New(), TenantID: uuid.New(), Ref: "host:FIN-01", Name: "Finance WS",
		Kind: "host", Criticality: "high",
		Owner: "internal-analyst-pod-3", Tags: []string{"internal:playbook-x"}, // MUST NOT leak
	}}
	vulns := []vulnerability.Vuln{{
		ID: uuid.New(), TenantID: uuid.New(), Ref: "host:FIN-01", CVE: "CVE-2026-0001",
		Title: "Critical RCE", Severity: "critical", CVSS: 9.8, Exploited: true, Status: "open",
	}}
	fws := []compliance.Framework{
		{Key: "cis", Name: "CIS Controls", Version: "8.1", Enabled: true},
		{Key: "disabled_fw", Name: "Not Adopted", Version: "1", Enabled: false}, // must be skipped
	}
	cov := &compliance.Coverage{Framework: "cis", Score: 75, Summary: map[string]int{"met": 9, "gap": 3}}
	return NewHandler(fakeInc{}, fakeAlerts{}, fakePolicy{DefaultDisclosurePolicy()}, fakeReg{}, fakeScope{},
		fakeAssets{list: assets}, fakeVulns{list: vulns}, fakeCompliance{fws, cov}, nil)
}

func TestSliceB_ProviderAndRegulatorRefused(t *testing.T) {
	h := sliceBHandler()
	for name, fn := range map[string]func(http.ResponseWriter, *http.Request){
		"assets": h.ListAssets, "vulns": h.ListVulnerabilities, "compliance": h.ListCompliance,
	} {
		if w := call(fn, provider, ""); w.Code != http.StatusForbidden {
			t.Errorf("provider on customer %s: got %d, want 403", name, w.Code)
		}
		if w := call(fn, regulator, ""); w.Code != http.StatusForbidden {
			t.Errorf("regulator on customer %s: got %d, want 403", name, w.Code)
		}
	}
}

func TestSliceB_CustomerAssetsRedacted(t *testing.T) {
	w := call(sliceBHandler().ListAssets, custViewer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("customer ListAssets: got %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "host:FIN-01") || !strings.Contains(body, "Finance WS") {
		t.Errorf("customer asset view missing expected safe fields: %s", body)
	}
	if strings.Contains(body, "internal-analyst-pod-3") {
		t.Errorf("SECURITY: internal asset owner leaked to customer: %s", body)
	}
	if strings.Contains(body, "playbook-x") {
		t.Errorf("SECURITY: internal asset tag leaked to customer: %s", body)
	}
}

func TestSliceB_AssetDetail_BlastRadiusRedacted(t *testing.T) {
	a := asset.Asset{ID: uuid.New(), TenantID: uuid.New(), Ref: "host:FIN-01", Name: "Finance WS", Kind: "host", Criticality: "high", Owner: "internal-pod-3", Tags: []string{"internal:x"}}
	vulns := []vulnerability.Vuln{{ID: uuid.New(), Ref: "host:FIN-01", CVE: "CVE-2026-0001", Title: "RCE", Severity: "critical", Status: "open"}}
	als := []alert.Alert{{ID: uuid.New(), Title: "Suspicious login", Severity: "high", Status: "new", TargetRef: "host:FIN-01"}}
	h := NewHandler(fakeInc{}, fakeAlerts{list: als}, fakePolicy{DefaultDisclosurePolicy()}, fakeReg{}, fakeScope{},
		fakeAssets{get: &a}, fakeVulns{byRefs: vulns}, fakeCompliance{}, nil)

	if w := call(h.GetAsset, provider, uuid.NewString()); w.Code != http.StatusForbidden {
		t.Errorf("provider on GetAsset: got %d, want 403", w.Code)
	}
	w := call(h.GetAsset, custViewer, uuid.NewString())
	if w.Code != http.StatusOK {
		t.Fatalf("customer GetAsset: got %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"host:FIN-01", "CVE-2026-0001", "Suspicious login"} {
		if !strings.Contains(body, want) {
			t.Errorf("asset detail missing blast-radius item %q: %s", want, body)
		}
	}
	if strings.Contains(body, "internal-pod-3") || strings.Contains(body, "internal:x") {
		t.Errorf("SECURITY: internal asset field leaked in detail: %s", body)
	}
	// a not-found asset → 404 (fakeAssets.get nil)
	h2 := NewHandler(fakeInc{}, fakeAlerts{}, fakePolicy{DefaultDisclosurePolicy()}, fakeReg{}, fakeScope{}, fakeAssets{}, fakeVulns{}, fakeCompliance{}, nil)
	if w := call(h2.GetAsset, custViewer, uuid.NewString()); w.Code != http.StatusNotFound {
		t.Errorf("missing asset: got %d, want 404", w.Code)
	}
}

func TestSliceB_CustomerVulnsProjected(t *testing.T) {
	w := call(sliceBHandler().ListVulnerabilities, custViewer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("customer ListVulnerabilities: got %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "CVE-2026-0001") || !strings.Contains(body, "critical") {
		t.Errorf("customer vuln view missing expected fields: %s", body)
	}
}

func TestSliceB_CustomerComplianceSkipsDisabled(t *testing.T) {
	w := call(sliceBHandler().ListCompliance, custViewer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("customer ListCompliance: got %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "cis") || !strings.Contains(body, "75") {
		t.Errorf("enabled framework not projected with score: %s", body)
	}
	if strings.Contains(body, "disabled_fw") {
		t.Errorf("disabled framework should be skipped, but appeared: %s", body)
	}
}

// detailHandler wires a coverage with a function→control tree carrying an INTERNAL note/evidence, to prove the
// drill-down projects per-control status/description but drops the internal assessment fields.
func detailHandler() *Handler {
	fws := []compliance.Framework{{Key: "cis", Name: "CIS Controls", Version: "8.1", Enabled: true}}
	cov := &compliance.Coverage{
		Framework: "cis", Score: 50, Summary: map[string]int{"met": 1, "gap": 1},
		Functions: []compliance.FunctionAssessment{{
			ControlRef: "CIS-5", Title: "Account Management", Status: "partial",
			Controls: []compliance.ControlAssessment{
				{ControlRef: "CIS-5.1", Title: "Inventory accounts", Status: "met", Source: "auto", Note: "INTERNAL analyst note", EvidenceRef: "s3://internal/evidence-x"},
				{ControlRef: "CIS-5.2", Title: "MFA for admins", Status: "gap", Source: "manual", Note: "INTERNAL remediation plan"},
			},
		}},
	}
	ctrls := []compliance.Control{
		{ControlRef: "CIS-5.1", Description: "Maintain an inventory of all accounts."},
		{ControlRef: "CIS-5.2", Description: "Require MFA for all administrative access."},
	}
	fc := fakeComplianceDetail{fws: fws, cov: cov, ctrls: ctrls}
	return NewHandler(fakeInc{}, fakeAlerts{}, fakePolicy{DefaultDisclosurePolicy()}, fakeReg{}, fakeScope{},
		fakeAssets{}, fakeVulns{}, fc, nil)
}

type fakeComplianceDetail struct {
	fws   []compliance.Framework
	cov   *compliance.Coverage
	ctrls []compliance.Control
}

func (f fakeComplianceDetail) ListFrameworks(_ context.Context, _ uuid.UUID) ([]compliance.Framework, error) {
	return f.fws, nil
}
func (f fakeComplianceDetail) Assess(_ context.Context, _ uuid.UUID, _ string) (*compliance.Coverage, error) {
	return f.cov, nil
}
func (f fakeComplianceDetail) ListControls(_ context.Context, _ uuid.UUID, _ string) ([]compliance.Control, error) {
	return f.ctrls, nil
}

func TestSliceB_ComplianceDetail_DrillDownRedacted(t *testing.T) {
	h := detailHandler()
	// provider refused
	if w := call(h.GetCompliance, provider, ""); w.Code != http.StatusForbidden {
		t.Errorf("provider on GetCompliance: got %d, want 403", w.Code)
	}
	// customer: per-control status + description present; internal note/evidence absent
	r := reqWithKey(h.GetCompliance, custViewer, "cis")
	if r.Code != http.StatusOK {
		t.Fatalf("customer GetCompliance: got %d, want 200", r.Code)
	}
	body := r.Body.String()
	for _, want := range []string{"CIS-5.2", "MFA for admins", "gap", "Require MFA for all administrative access."} {
		if !strings.Contains(body, want) {
			t.Errorf("drill-down missing customer-safe %q: %s", want, body)
		}
	}
	for _, leak := range []string{"INTERNAL analyst note", "INTERNAL remediation plan", "s3://internal/evidence-x"} {
		if strings.Contains(body, leak) {
			t.Errorf("SECURITY: internal assessment field leaked to customer: %q", leak)
		}
	}
	// unknown framework key → 404 (existence not revealed)
	if w := reqWithKey(h.GetCompliance, custViewer, "nonexistent"); w.Code != http.StatusNotFound {
		t.Errorf("unknown framework key: got %d, want 404", w.Code)
	}
}
