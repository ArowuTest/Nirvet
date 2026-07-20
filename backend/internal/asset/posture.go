package asset

// §6.15 #179 Asset slice B (read-only) — attack-surface/exposure posture, identity inventory, and a TRANSPARENT
// per-asset confidence signal. Every number is computed from REAL rows (assets ⋈ vulnerabilities on the canonical
// ref), tenant-scoped under RLS. Nothing is fabricated: an "exposed" asset is one that actually has an active
// (open/remediating) vulnerability; "confidence" is an explicitly-defined inventory data-completeness + monitoring-
// coverage signal (NOT a trust score), and it exposes the exact signals that produced it.

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// activeVulnStatuses are the vulnerability statuses that count as live exposure (not resolved/accepted).
var activeVulnStatuses = []string{"open", "remediating"}

// postureTopN is how many top-exposed assets the posture summary returns.
const postureTopN = 10

// Posture returns the tenant's attack-surface summary (service passthrough; RLS-scoped read).
func (s *Service) Posture(ctx context.Context, tenantID uuid.UUID) (*Posture, error) {
	return s.repo.Posture(ctx, tenantID, postureTopN)
}

// Identities returns the tenant's identity (user-kind) inventory with per-asset confidence.
func (s *Service) Identities(ctx context.Context, tenantID uuid.UUID) ([]IdentityAsset, error) {
	return s.repo.Identities(ctx, tenantID)
}

// ExposedAsset is one asset that currently carries active vulnerabilities.
type ExposedAsset struct {
	ID          uuid.UUID `json:"id"`
	Ref         string    `json:"ref"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Criticality string    `json:"criticality"`
	OpenVulns   int       `json:"open_vulns"`
	MaxSeverity string    `json:"max_severity"`
}

// Posture is the tenant's attack-surface summary: inventory breakdowns + live vulnerability exposure.
type Posture struct {
	TotalAssets         int            `json:"total_assets"`
	ByKind              map[string]int `json:"by_kind"`
	ByCriticality       map[string]int `json:"by_criticality"`
	OpenVulns           int            `json:"open_vulns"`
	OpenVulnsBySeverity map[string]int `json:"open_vulns_by_severity"`
	ExposedAssets       int            `json:"exposed_assets"` // distinct assets with >=1 active vuln
	TopExposed          []ExposedAsset `json:"top_exposed"`
}

// Confidence is a TRANSPARENT inventory-quality signal for one asset. Score is the count of positive signals (0..4);
// Signals lists exactly which ones fired. It measures how complete + monitored the inventory record is — NOT how
// trustworthy the asset is. Naming the signals keeps it honest: the UI shows WHY the score is what it is.
type Confidence struct {
	Score   int      `json:"score"`   // 0..4
	Label   string   `json:"label"`   // low | medium | high
	Signals []string `json:"signals"` // named, positive
}

// assetConfidence derives the completeness signal from real fields + whether the asset appears in vuln telemetry.
func assetConfidence(a Asset, vulnScanned bool) Confidence {
	var sig []string
	if a.Name != "" {
		sig = append(sig, "named")
	}
	if a.Owner != "" {
		sig = append(sig, "owner_assigned")
	}
	if len(a.Tags) > 0 {
		sig = append(sig, "tagged")
	}
	if vulnScanned {
		sig = append(sig, "vuln_scanned")
	}
	label := "low"
	switch {
	case len(sig) >= 4:
		label = "high"
	case len(sig) >= 2:
		label = "medium"
	}
	return Confidence{Score: len(sig), Label: label, Signals: sig}
}

// IdentityAsset is a user-kind asset with its live-vuln count and completeness signal — the identity inventory row.
type IdentityAsset struct {
	Asset
	OpenVulns  int        `json:"open_vulns"`
	Confidence Confidence `json:"confidence"`
}

// Posture assembles the attack-surface summary for a tenant (RLS-scoped). Pure reads; no mutation.
func (r *Repository) Posture(ctx context.Context, tenantID uuid.UUID, topN int) (*Posture, error) {
	p := &Posture{ByKind: map[string]int{}, ByCriticality: map[string]int{}, OpenVulnsBySeverity: map[string]int{}}
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Inventory breakdowns.
		rows, e := tx.Query(ctx, `SELECT kind, criticality, count(*) FROM assets GROUP BY kind, criticality`)
		if e != nil {
			return e
		}
		for rows.Next() {
			var kind, crit string
			var n int
			if e := rows.Scan(&kind, &crit, &n); e != nil {
				rows.Close()
				return e
			}
			p.ByKind[kind] += n
			p.ByCriticality[crit] += n
			p.TotalAssets += n
		}
		rows.Close()
		if e := rows.Err(); e != nil {
			return e
		}

		// Live vulnerability exposure by severity.
		vrows, e := tx.Query(ctx,
			`SELECT severity, count(*) FROM vulnerabilities WHERE status = ANY($1) GROUP BY severity`, activeVulnStatuses)
		if e != nil {
			return e
		}
		for vrows.Next() {
			var sev string
			var n int
			if e := vrows.Scan(&sev, &n); e != nil {
				vrows.Close()
				return e
			}
			p.OpenVulnsBySeverity[sev] += n
			p.OpenVulns += n
		}
		vrows.Close()
		if e := vrows.Err(); e != nil {
			return e
		}

		// Distinct assets that actually exist AND carry an active vuln (join on the canonical ref).
		if e := tx.QueryRow(ctx,
			`SELECT count(DISTINCT a.ref) FROM assets a
			   JOIN vulnerabilities v ON v.tenant_id = a.tenant_id AND v.ref = a.ref
			  WHERE v.status = ANY($1)`, activeVulnStatuses).Scan(&p.ExposedAssets); e != nil {
			return e
		}

		// Top-exposed assets: ordered by asset criticality then active-vuln count, with the worst vuln severity.
		trows, e := tx.Query(ctx, `
			SELECT a.id, a.ref, a.name, a.kind, a.criticality, count(v.*) AS open_vulns,
			       max(CASE v.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS sev_rank
			  FROM assets a
			  JOIN vulnerabilities v ON v.tenant_id = a.tenant_id AND v.ref = a.ref
			 WHERE v.status = ANY($1)
			 GROUP BY a.id, a.ref, a.name, a.kind, a.criticality
			 ORDER BY CASE a.criticality WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
			          open_vulns DESC, sev_rank DESC
			 LIMIT $2`, activeVulnStatuses, topN)
		if e != nil {
			return e
		}
		defer trows.Close()
		for trows.Next() {
			var ea ExposedAsset
			var sevRank int
			if e := trows.Scan(&ea.ID, &ea.Ref, &ea.Name, &ea.Kind, &ea.Criticality, &ea.OpenVulns, &sevRank); e != nil {
				return e
			}
			ea.MaxSeverity = sevRankLabel(sevRank)
			p.TopExposed = append(p.TopExposed, ea)
		}
		return trows.Err()
	})
	return p, err
}

func sevRankLabel(rank int) string {
	switch rank {
	case 4:
		return "critical"
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	default:
		return ""
	}
}

// Identities returns the tenant's user-kind assets (identity inventory), each with its active-vuln count and the
// completeness confidence signal. RLS-scoped read.
func (r *Repository) Identities(ctx context.Context, tenantID uuid.UUID) ([]IdentityAsset, error) {
	var out []IdentityAsset
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `
			SELECT `+prefixed("a", assetCols)+`,
			       COALESCE((SELECT count(*) FROM vulnerabilities v
			                  WHERE v.tenant_id = a.tenant_id AND v.ref = a.ref AND v.status = ANY($1)), 0) AS open_vulns
			  FROM assets a
			 WHERE a.kind = 'user'
			 ORDER BY a.created_at DESC
			 LIMIT 500`, activeVulnStatuses)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var ia IdentityAsset
			if e := rows.Scan(&ia.ID, &ia.TenantID, &ia.Ref, &ia.Name, &ia.Kind, &ia.Criticality, &ia.Owner, &ia.Tags, &ia.CreatedAt, &ia.OpenVulns); e != nil {
				return e
			}
			ia.Confidence = assetConfidence(ia.Asset, ia.OpenVulns > 0)
			out = append(out, ia)
		}
		return rows.Err()
	})
	return out, err
}

// prefixed qualifies a comma-separated column list with a table alias (e.g. "id, ref" → "a.id, a.ref").
func prefixed(alias, cols string) string {
	out := ""
	col := ""
	flush := func() {
		if col == "" {
			return
		}
		if out != "" {
			out += ", "
		}
		out += alias + "." + col
		col = ""
	}
	for _, c := range cols {
		switch c {
		case ',':
			flush()
		case ' ':
			// skip
		default:
			col += string(c)
		}
	}
	flush()
	return out
}
