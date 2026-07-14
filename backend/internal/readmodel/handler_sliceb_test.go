package readmodel

// Slice B adversarial read-matrix: the customer asset/vuln/compliance endpoints must (1) refuse a non-customer
// audience and (2) project ONLY customer-safe fields — internal asset owner/tags never reach the customer.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/compliance"
	"github.com/ArowuTest/nirvet/internal/vulnerability"
	"github.com/google/uuid"
)

type fakeAssets struct{ list []asset.Asset }

func (f fakeAssets) List(_ context.Context, _ uuid.UUID) ([]asset.Asset, error) { return f.list, nil }

type fakeVulns struct{ list []vulnerability.Vuln }

func (f fakeVulns) List(_ context.Context, _ uuid.UUID, _, _ string) ([]vulnerability.Vuln, error) {
	return f.list, nil
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
		fakeAssets{assets}, fakeVulns{vulns}, fakeCompliance{fws, cov}, nil)
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
