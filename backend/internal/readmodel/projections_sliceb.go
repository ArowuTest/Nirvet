package readmodel

// Slice B customer-audience projections: assets, vulnerabilities, compliance. Same positive-allowlist discipline
// as Slice A (projections.go) — each *View names ONLY customer-safe fields, so a provider-internal field cannot
// leak (there is no struct field to hold it). These compose over the customer's OWN tenant reads (RLS-scoped);
// they add no table and no cross-tenant path. The reflection test (audience_test.go) asserts these carry no
// internal identifiers.

import (
	"time"

	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/compliance"
	"github.com/ArowuTest/nirvet/internal/vulnerability"
)

// ---- Assets (customer sees their own inventory: what/where/how-critical) ----

// CustomerAssetView is the allowlist projection of an asset. It exposes the customer-facing identity and
// business criticality of their own asset. WITHHELD by construction: Owner (an internal assignment an MSSP may
// use operationally), Tags (may carry internal pod/playbook labels), TenantID, and the internal row ID.
type CustomerAssetView struct {
	Ref         string    `json:"ref"` // canonical reference, e.g. host:FIN-01
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Criticality string    `json:"criticality"`
	CreatedAt   time.Time `json:"created_at"`
}

// ProjectAssetForCustomer builds the customer asset view.
func ProjectAssetForCustomer(a asset.Asset) CustomerAssetView {
	return CustomerAssetView{
		Ref:         a.Ref,
		Name:        a.Name,
		Kind:        a.Kind,
		Criticality: a.Criticality,
		CreatedAt:   a.CreatedAt,
	}
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
