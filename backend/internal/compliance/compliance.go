// Package compliance maps platform capabilities and live signals to control frameworks and produces a
// per-tenant assessment (SRS §6.14). Frameworks and controls are DB config (seeded global templates +
// tenant-custom); the control→signal MAPPING is config, while the signal RESOLVERS that inspect live
// state (audit immutability, RLS, detection coverage, incident response) are code. A control with no
// auto-signal is `gap` until manually assessed — nothing is ever fabricated as "met".
package compliance

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Framework is a control-framework template (global) or a tenant-custom framework.
type Framework struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"`
	Key         string     `json:"key"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Description string     `json:"description"`
	Enabled     bool       `json:"enabled"`
}

// Control is one control within a framework. AutoSignal names the live signal that proves it (config);
// an empty AutoSignal means the control is a rollup (a function whose status is derived from children).
type Control struct {
	ID           uuid.UUID      `json:"id"`
	TenantID     *uuid.UUID     `json:"tenant_id,omitempty"`
	FrameworkKey string         `json:"framework_key"`
	ControlRef   string         `json:"control_ref"`
	ParentRef    string         `json:"parent_ref"`
	Title        string         `json:"title"`
	Description  string         `json:"description"`
	Weight       int            `json:"weight"`
	AutoSignal   string         `json:"auto_signal"`
	AutoConfig   map[string]any `json:"auto_config"`
}

// ControlStatus is the assessed status of a control for a tenant (auto cache or manual override).
type ControlStatus struct {
	FrameworkKey string     `json:"framework_key"`
	ControlRef   string     `json:"control_ref"`
	Status       string     `json:"status"`
	Score        int        `json:"score"`
	Source       string     `json:"source"`
	Note         string     `json:"note"`
	EvidenceRef  string     `json:"evidence_ref,omitempty"`
	AssessedBy   *uuid.UUID `json:"assessed_by,omitempty"`
}

// Repository persists frameworks, controls, and status; and runs the read-only COUNT probes that the
// signal resolvers use to measure live coverage.
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// ListFrameworks returns global + own frameworks.
func (r *Repository) ListFrameworks(ctx context.Context, tenantID uuid.UUID) ([]Framework, error) {
	var out []Framework
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, key, name, version, description, enabled
			   FROM compliance_frameworks WHERE enabled = true ORDER BY key`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f Framework
			if err := rows.Scan(&f.ID, &f.TenantID, &f.Key, &f.Name, &f.Version, &f.Description, &f.Enabled); err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// ListControls returns global + own controls for a framework, parents before children.
func (r *Repository) ListControls(ctx context.Context, tenantID uuid.UUID, frameworkKey string) ([]Control, error) {
	var out []Control
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, framework_key, control_ref, parent_ref, title, description, weight, auto_signal, auto_config
			   FROM compliance_controls WHERE framework_key = $1
			  ORDER BY (parent_ref <> '') , control_ref`, frameworkKey)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Control
			if err := rows.Scan(&c.ID, &c.TenantID, &c.FrameworkKey, &c.ControlRef, &c.ParentRef,
				&c.Title, &c.Description, &c.Weight, &c.AutoSignal, &c.AutoConfig); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// ManualStatuses returns the tenant's stored manual overrides for a framework, keyed by control_ref.
func (r *Repository) ManualStatuses(ctx context.Context, tenantID uuid.UUID, frameworkKey string) (map[string]ControlStatus, error) {
	out := map[string]ControlStatus{}
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT framework_key, control_ref, status, score, source, note, evidence_ref, assessed_by
			   FROM compliance_control_status WHERE framework_key = $1 AND source = 'manual'`, frameworkKey)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s ControlStatus
			if err := rows.Scan(&s.FrameworkKey, &s.ControlRef, &s.Status, &s.Score, &s.Source, &s.Note, &s.EvidenceRef, &s.AssessedBy); err != nil {
				return err
			}
			out[s.ControlRef] = s
		}
		return rows.Err()
	})
	return out, err
}

// UpsertManualStatus records a manual override for a control (COMP-004).
func (r *Repository) UpsertManualStatus(ctx context.Context, tenantID uuid.UUID, s ControlStatus, assessedBy uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO compliance_control_status
			   (tenant_id, framework_key, control_ref, status, score, source, note, evidence_ref, assessed_by, assessed_at)
			 VALUES ($1,$2,$3,$4,$5,'manual',$6,$7,$8, now())
			 ON CONFLICT (tenant_id, framework_key, control_ref) DO UPDATE SET
			   status=EXCLUDED.status, score=EXCLUDED.score, source='manual', note=EXCLUDED.note,
			   evidence_ref=EXCLUDED.evidence_ref, assessed_by=EXCLUDED.assessed_by, assessed_at=now()`,
			tenantID, s.FrameworkKey, s.ControlRef, s.Status, s.Score, s.Note, s.EvidenceRef, assessedBy)
		return err
	})
}

// count runs a read-only COUNT within the tenant context. The query is a fixed literal chosen by a code
// resolver (never built from config), so there is no injection surface.
func (r *Repository) count(ctx context.Context, tenantID uuid.UUID, query string) (int, error) {
	var n int
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, query).Scan(&n)
	})
	return n, err
}
