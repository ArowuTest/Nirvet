package readmodel

// Slice B customer-audience projections: assets, vulnerabilities, compliance. Same positive-allowlist discipline
// as Slice A (projections.go) — each *View names ONLY customer-safe fields, so a provider-internal field cannot
// leak (there is no struct field to hold it). These compose over the customer's OWN tenant reads (RLS-scoped);
// they add no table and no cross-tenant path. The reflection test (audience_test.go) asserts these carry no
// internal identifiers.

import (
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/compliance"
	"github.com/ArowuTest/nirvet/internal/riskscore"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/vulnerability"
	"github.com/google/uuid"
)

// ---- Assets (customer sees their own inventory: what/where/how-critical) ----

// CustomerAssetView is the allowlist projection of an asset. It exposes the customer-facing identity and
// business criticality of their own asset. AssetID is the customer's OWN asset handle (used only to open the
// detail view — not an internal secret). WITHHELD by construction: Owner (an internal assignment an MSSP may use
// operationally), Tags (may carry internal pod/playbook labels), TenantID.
type CustomerAssetView struct {
	AssetID     uuid.UUID `json:"asset_id"`
	Ref         string    `json:"ref"` // canonical reference, e.g. host:FIN-01
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Criticality string    `json:"criticality"`
	CreatedAt   time.Time `json:"created_at"`
}

// ProjectAssetForCustomer builds the customer asset view.
func ProjectAssetForCustomer(a asset.Asset) CustomerAssetView {
	return CustomerAssetView{
		AssetID:     a.ID,
		Ref:         a.Ref,
		Name:        a.Name,
		Kind:        a.Kind,
		Criticality: a.Criticality,
		CreatedAt:   a.CreatedAt,
	}
}

// CustomerAssetDetailView is the drill-down for one asset: its identity/criticality plus its blast radius —
// the open vulnerabilities on it and the alerts that targeted it. Composed from three RLS-scoped reads over the
// customer's own tenant; every nested item is itself a customer *View (no internal field can appear).
type CustomerAssetDetailView struct {
	CustomerAssetView
	Vulnerabilities []CustomerVulnerabilityView `json:"vulnerabilities"`
	Alerts          []CustomerAlertView         `json:"alerts"`
}

// ProjectAssetDetailForCustomer composes the asset view with its open vulns + targeting alerts, each projected.
func ProjectAssetDetailForCustomer(a asset.Asset, vulns []vulnerability.Vuln, alerts []alert.Alert) CustomerAssetDetailView {
	d := CustomerAssetDetailView{
		CustomerAssetView: ProjectAssetForCustomer(a),
		Vulnerabilities:   []CustomerVulnerabilityView{},
		Alerts:            []CustomerAlertView{},
	}
	for _, v := range vulns {
		d.Vulnerabilities = append(d.Vulnerabilities, ProjectVulnForCustomer(v))
	}
	for _, al := range alerts {
		d.Alerts = append(d.Alerts, ProjectAlertForCustomer(al))
	}
	return d
}

// ---- Vulnerabilities (customer sees exposure on their own estate) ----

// CustomerVulnerabilityView is the allowlist projection of a vulnerability. Everything here is the customer's own
// exposure data — CVE/severity/affected-asset/remediation timeline. WITHHELD: TenantID and the internal row ID.
type CustomerVulnerabilityView struct {
	Ref            string     `json:"ref"` // affected asset ref (the customer's own host/user)
	CVE            string     `json:"cve"`
	Title          string     `json:"title"`
	Severity       string     `json:"severity"`
	CVSS           float64    `json:"cvss"`
	Exploited      bool       `json:"exploited"`
	Status         string     `json:"status"`
	RemediationDue *time.Time `json:"remediation_due,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// ProjectVulnForCustomer builds the customer vulnerability view.
func ProjectVulnForCustomer(v vulnerability.Vuln) CustomerVulnerabilityView {
	return CustomerVulnerabilityView{
		Ref:            v.Ref,
		CVE:            v.CVE,
		Title:          v.Title,
		Severity:       v.Severity,
		CVSS:           v.CVSS,
		Exploited:      v.Exploited,
		Status:         v.Status,
		RemediationDue: v.RemediationDue,
		CreatedAt:      v.CreatedAt,
	}
}

// ---- Compliance (customer sees their own framework coverage posture) ----

// CustomerComplianceView is the allowlist projection of one framework's coverage. It exposes the framework
// identity + the computed coverage score + the status-count summary (a low-cardinality map of control status →
// count, e.g. {"met":9,"gap":3}). WITHHELD: control-level internal notes, control weights, and evidence
// pointers — none of which have a field here.
type CustomerComplianceView struct {
	Key     string         `json:"key"`
	Name    string         `json:"name"`
	Version string         `json:"version"`
	Score   int            `json:"score"`
	Summary map[string]int `json:"summary"`
}

// ProjectComplianceForCustomer builds the customer compliance view from a framework + its assessed coverage.
func ProjectComplianceForCustomer(f compliance.Framework, cov *compliance.Coverage) CustomerComplianceView {
	v := CustomerComplianceView{Key: f.Key, Name: f.Name, Version: f.Version, Summary: map[string]int{}}
	if cov != nil {
		v.Score = cov.Score
		for k, n := range cov.Summary {
			v.Summary[k] = n
		}
	}
	return v
}

// ---- Compliance DETAIL (drill-down: which controls are met vs. gap, and what each requires) ----

// CustomerComplianceControlView is one control's customer-facing assessment: its reference, what it requires
// (title + framework-authored description), and whether it is met/partial/gap. WITHHELD by construction: the
// internal assessment Source (auto/manual), the analyst-authored Note, the EvidenceRef pointer, AssessedBy,
// Weight, and the AutoSignal/AutoConfig detection wiring — none of which have a field here.
type CustomerComplianceControlView struct {
	ControlRef  string `json:"control_ref"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"` // met | partial | gap | not_applicable
}

// CustomerComplianceFunctionView is a top-level control (function) with its rolled-up status and child controls.
// Description is populated for FLAT frameworks (a top-level control with no children still describes what it
// requires); for a true function-with-children it is typically empty and the detail lives on the child controls.
type CustomerComplianceFunctionView struct {
	ControlRef  string                          `json:"control_ref"`
	Title       string                          `json:"title"`
	Description string                          `json:"description"`
	Status      string                          `json:"status"`
	Controls    []CustomerComplianceControlView `json:"controls"`
}

// CustomerComplianceDetailView is the drill-down of one framework: the summary score/counts plus the function→
// control tree with per-control status. This is what lets a customer see EXACTLY which controls are the gaps.
type CustomerComplianceDetailView struct {
	Key       string                           `json:"key"`
	Name      string                           `json:"name"`
	Version   string                           `json:"version"`
	Score     int                              `json:"score"`
	Summary   map[string]int                   `json:"summary"`
	Functions []CustomerComplianceFunctionView `json:"functions"`
}

// ---- SOAR approvals awaiting the customer (SB3) ----

// CustomerApprovalView is the customer-safe summary of a run awaiting the customer's approval: which playbook, on
// which of their own incidents, since when. Internal step detail / requester / internal approver are absent.
type CustomerApprovalView struct {
	RunID        uuid.UUID  `json:"run_id"`
	PlaybookName string     `json:"playbook_name"`
	IncidentID   *uuid.UUID `json:"incident_id,omitempty"`
	CreatedAt    string     `json:"created_at"`
}

// ProjectApprovalForCustomer maps the soar summary item to the customer view (both are already allowlists).
func ProjectApprovalForCustomer(a soar.CustomerApprovalItem) CustomerApprovalView {
	return CustomerApprovalView{RunID: a.RunID, PlaybookName: a.PlaybookName, IncidentID: a.IncidentID, CreatedAt: a.CreatedAt}
}

// ---- Risk score (composite posture — aggregate-safe about the customer's OWN estate) ----

// CustomerRiskScoreView is the customer projection of the composite risk score. Every field is an aggregate/label
// about the customer's own estate (composite + band + per-component risk with count-only drivers) — there is no
// per-record content or internal field on riskscore.Score or riskscore.Component, so it is customer-safe by
// construction. Kept as a named *View so the audience boundary stays uniform and the reflection test covers it.
type CustomerRiskScoreView struct {
	Composite  int                   `json:"composite"`
	Band       string                `json:"band"`
	Tone       string                `json:"tone"`
	Components []riskscore.Component `json:"components"`
}

// ProjectRiskScoreForCustomer builds the customer risk-score view (empty-but-valid when the score is nil).
func ProjectRiskScoreForCustomer(s *riskscore.Score) CustomerRiskScoreView {
	v := CustomerRiskScoreView{Components: []riskscore.Component{}}
	if s != nil {
		v.Composite, v.Band, v.Tone = s.Composite, s.Band, s.Tone
		if s.Components != nil {
			v.Components = s.Components
		}
	}
	return v
}

// ProjectComplianceDetailForCustomer merges the assessed coverage (per-control status) with the control
// catalogue (per-control description) into the customer detail view. Descriptions are looked up by control_ref;
// the internal ControlAssessment fields (source/note/evidence) are never carried into the *View.
func ProjectComplianceDetailForCustomer(f compliance.Framework, cov *compliance.Coverage, controls []compliance.Control) CustomerComplianceDetailView {
	descByRef := make(map[string]string, len(controls))
	for _, c := range controls {
		descByRef[c.ControlRef] = c.Description
	}
	v := CustomerComplianceDetailView{Key: f.Key, Name: f.Name, Version: f.Version, Summary: map[string]int{}}
	if cov == nil {
		return v
	}
	v.Score = cov.Score
	for k, n := range cov.Summary {
		v.Summary[k] = n
	}
	for _, fn := range cov.Functions {
		fv := CustomerComplianceFunctionView{ControlRef: fn.ControlRef, Title: fn.Title, Description: descByRef[fn.ControlRef], Status: fn.Status, Controls: []CustomerComplianceControlView{}}
		for _, c := range fn.Controls {
			fv.Controls = append(fv.Controls, CustomerComplianceControlView{
				ControlRef: c.ControlRef, Title: c.Title, Description: descByRef[c.ControlRef], Status: c.Status,
			})
		}
		v.Functions = append(v.Functions, fv)
	}
	return v
}
