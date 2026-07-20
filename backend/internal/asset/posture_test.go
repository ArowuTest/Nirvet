package asset

// §6.15 #179 Asset slice B tests. assetConfidence is DB-free (transparent signal function). Posture + Identities are
// DB-gated (RequireDSN): they assert the exposure join counts REAL active vulns and that resolved vulns don't count.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestAssetConfidence: the completeness signal counts exactly the populated fields + vuln coverage, and labels honestly.
func TestAssetConfidence(t *testing.T) {
	// Empty asset, no vuln telemetry → score 0, low, no signals.
	c := assetConfidence(Asset{}, false)
	if c.Score != 0 || c.Label != "low" || len(c.Signals) != 0 {
		t.Fatalf("empty asset: %+v", c)
	}
	// Named + owner (2 signals) → medium.
	c = assetConfidence(Asset{Name: "FIN-01", Owner: "ops@acme"}, false)
	if c.Score != 2 || c.Label != "medium" {
		t.Fatalf("named+owner: %+v", c)
	}
	// Full: name + owner + tags + vuln-scanned → score 4, high, all signals named.
	c = assetConfidence(Asset{Name: "n", Owner: "o", Tags: []string{"prod"}}, true)
	if c.Score != 4 || c.Label != "high" {
		t.Fatalf("full: %+v", c)
	}
	want := map[string]bool{"named": true, "owner_assigned": true, "tagged": true, "vuln_scanned": true}
	for _, s := range c.Signals {
		if !want[s] {
			t.Fatalf("unexpected signal %q", s)
		}
	}
	if len(c.Signals) != 4 {
		t.Fatalf("expected 4 named signals, got %v", c.Signals)
	}
}

// seedVuln inserts a vulnerability for an asset ref (test helper; the vuln domain owns the write path in prod).
func seedVuln(t *testing.T, db *database.DB, tenantID uuid.UUID, ref, cve, severity, status string) {
	t.Helper()
	if err := db.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO vulnerabilities (tenant_id, ref, cve, severity, status) VALUES (app_current_tenant(),$1,$2,$3,$4)
			 ON CONFLICT (tenant_id, ref, cve) DO UPDATE SET severity=EXCLUDED.severity, status=EXCLUDED.status`,
			ref, cve, severity, status)
		return e
	}); err != nil {
		t.Fatalf("seed vuln: %v", err)
	}
}

// TestPosture_ExposureJoin: an asset with an OPEN vuln is exposed; a resolved vuln does not count.
func TestPosture_ExposureJoin(t *testing.T) {
	svc, p, db := bulkSvc(t)
	ctx := context.Background()

	// Two assets: a critical host with an open high vuln, and a low host whose only vuln is resolved.
	if _, err := svc.Create(ctx, p, CreateInput{Ref: "host:FIN-01", Name: "FIN-01", Kind: "host", Criticality: "critical", Owner: "ops"}); err != nil {
		t.Fatalf("create a: %v", err)
	}
	if _, err := svc.Create(ctx, p, CreateInput{Ref: "host:WEB-02", Name: "WEB-02", Kind: "host", Criticality: "low"}); err != nil {
		t.Fatalf("create b: %v", err)
	}
	seedVuln(t, db, p.TenantID, "host:FIN-01", "CVE-1", "high", "open")
	seedVuln(t, db, p.TenantID, "host:FIN-01", "CVE-2", "critical", "remediating")
	seedVuln(t, db, p.TenantID, "host:WEB-02", "CVE-3", "high", "resolved") // resolved → not active

	pos, err := svc.Posture(ctx, p.TenantID)
	if err != nil {
		t.Fatalf("posture: %v", err)
	}
	if pos.TotalAssets != 2 {
		t.Fatalf("total assets: %d", pos.TotalAssets)
	}
	if pos.OpenVulns != 2 || pos.OpenVulnsBySeverity["high"] != 1 || pos.OpenVulnsBySeverity["critical"] != 1 {
		t.Fatalf("open vulns: %+v", pos)
	}
	if pos.ExposedAssets != 1 { // only FIN-01 has active vulns; WEB-02's is resolved
		t.Fatalf("exposed assets: %d (want 1)", pos.ExposedAssets)
	}
	if len(pos.TopExposed) != 1 || pos.TopExposed[0].Ref != "host:FIN-01" || pos.TopExposed[0].OpenVulns != 2 {
		t.Fatalf("top exposed: %+v", pos.TopExposed)
	}
	if pos.TopExposed[0].MaxSeverity != "critical" {
		t.Fatalf("max severity: %s (want critical)", pos.TopExposed[0].MaxSeverity)
	}
}

// TestIdentities_UserKindWithConfidence: only user-kind assets appear, with open-vuln count + confidence.
func TestIdentities_UserKindWithConfidence(t *testing.T) {
	svc, p, db := bulkSvc(t)
	ctx := context.Background()

	if _, err := svc.Create(ctx, p, CreateInput{Ref: "user:jane@acme", Name: "Jane", Kind: "user", Criticality: "high", Owner: "hr", Tags: []string{"admin"}}); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	if _, err := svc.Create(ctx, p, CreateInput{Ref: "host:SRV-1", Name: "SRV-1", Kind: "host", Criticality: "low"}); err != nil {
		t.Fatalf("create host: %v", err)
	}
	seedVuln(t, db, p.TenantID, "user:jane@acme", "CVE-9", "medium", "open")

	ids, err := svc.Identities(ctx, p.TenantID)
	if err != nil {
		t.Fatalf("identities: %v", err)
	}
	if len(ids) != 1 || ids[0].Ref != "user:jane@acme" {
		t.Fatalf("only user-kind assets in the identity inventory; got %+v", ids)
	}
	if ids[0].OpenVulns != 1 {
		t.Fatalf("identity open vulns: %d", ids[0].OpenVulns)
	}
	// name+owner+tags+vuln_scanned → confidence high (4 signals).
	if ids[0].Confidence.Score != 4 || ids[0].Confidence.Label != "high" {
		t.Fatalf("identity confidence: %+v", ids[0].Confidence)
	}
}
