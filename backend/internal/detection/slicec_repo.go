package detection

// §6.6 slice C persistence: test cases (DET-005), FP feedback (DET-007), coverage source set
// (DET-009), and per-tenant settings. All tenant-scoped via RLS; feedback is append-only.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GetRule loads a single rule visible to the tenant (own or global) for testing/stats. Returns
// nil (no error) when the rule is not visible.
func (r *Repository) GetRule(ctx context.Context, tenantID, id uuid.UUID) (*Rule, error) {
	var rule *Rule
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var rr Rule
		var cond []byte
		e := tx.QueryRow(ctx, `SELECT `+ruleCols+` FROM detection_rules WHERE id=$1`, id).
			Scan(&rr.ID, &rr.TenantID, &rr.Name, &rr.Description, &rr.Severity, &rr.Confidence,
				&rr.MITRE, &cond, &rr.Expression, &rr.Enabled, &rr.CreatedAt,
				&rr.Stage, &rr.Version, &rr.OwnerID, &rr.SourceDependencies)
		if e == pgx.ErrNoRows {
			return nil
		}
		if e != nil {
			return e
		}
		_ = json.Unmarshal(cond, &rr.Condition)
		rule = &rr
		return nil
	})
	return rule, err
}

// AddTestCase inserts a test case for a rule (DET-005).
func (r *Repository) AddTestCase(ctx context.Context, tenantID uuid.UUID, tc *TestCase, by uuid.UUID) error {
	sample, _ := json.Marshal(tc.Sample)
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var created time.Time
		if err := tx.QueryRow(ctx,
			`INSERT INTO detection_test_cases (id, tenant_id, rule_id, name, sample, expected_match, created_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`,
			tc.ID, tenantID, tc.RuleID, tc.Name, sample, tc.ExpectedMatch, by,
		).Scan(&created); err != nil {
			return err
		}
		tc.CreatedAt = created.Format(time.RFC3339)
		return nil
	})
}

// ListTestCases returns a rule's test cases.
func (r *Repository) ListTestCases(ctx context.Context, tenantID, ruleID uuid.UUID) ([]TestCase, error) {
	var out []TestCase
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, rule_id, name, sample, expected_match FROM detection_test_cases
			  WHERE rule_id=$1 ORDER BY created_at ASC`, ruleID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var tc TestCase
			var sample []byte
			if err := rows.Scan(&tc.ID, &tc.RuleID, &tc.Name, &sample, &tc.ExpectedMatch); err != nil {
				return err
			}
			_ = json.Unmarshal(sample, &tc.Sample)
			out = append(out, tc)
		}
		return rows.Err()
	})
	return out, err
}

// DeleteTestCase removes a test case; applied=false if not found in this tenant.
func (r *Repository) DeleteTestCase(ctx context.Context, tenantID, id uuid.UUID) (bool, error) {
	applied := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `DELETE FROM detection_test_cases WHERE id=$1`, id)
		if e != nil {
			return e
		}
		applied = ct.RowsAffected() == 1
		return nil
	})
	return applied, err
}

// RecordFeedback appends an append-only disposition feedback row (DET-007).
func (r *Repository) RecordFeedback(ctx context.Context, tenantID, ruleID uuid.UUID, alertID *uuid.UUID, disp Disposition, reason string, by uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO detection_feedback (tenant_id, rule_id, alert_id, disposition, reason, created_by)
			 VALUES ($1,$2,$3,$4,$5,$6)`,
			tenantID, ruleID, alertID, string(disp), reason, by)
		return err
	})
}

// FeedbackCounts returns per-disposition counts for one rule.
func (r *Repository) FeedbackCounts(ctx context.Context, tenantID, ruleID uuid.UUID) (map[Disposition]int, error) {
	out := map[Disposition]int{}
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT disposition, count(*) FROM detection_feedback WHERE rule_id=$1 GROUP BY disposition`, ruleID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d string
			var n int
			if err := rows.Scan(&d, &n); err != nil {
				return err
			}
			out[Disposition(d)] = n
		}
		return rows.Err()
	})
	return out, err
}

// ruleDisposition is one (rule, disposition, count) row for the tenant-wide tuning view.
type ruleDisposition struct {
	RuleID uuid.UUID
	Disp   Disposition
	Count  int
}

// FeedbackByRule returns per-(rule,disposition) counts across the tenant (tuning view).
func (r *Repository) FeedbackByRule(ctx context.Context, tenantID uuid.UUID) ([]ruleDisposition, error) {
	var out []ruleDisposition
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT rule_id, disposition, count(*) FROM detection_feedback GROUP BY rule_id, disposition`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rd ruleDisposition
			var d string
			if err := rows.Scan(&rd.RuleID, &d, &rd.Count); err != nil {
				return err
			}
			rd.Disp = Disposition(d)
			out = append(out, rd)
		}
		return rows.Err()
	})
	return out, err
}

// RecentSources returns the distinct event sources ingested for the tenant within the window
// (DET-009 coverage ground truth — what data is actually arriving, from raw_events).
func (r *Repository) RecentSources(ctx context.Context, tenantID uuid.UUID, windowDays int) (map[string]bool, error) {
	out := map[string]bool{}
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT DISTINCT source FROM raw_events
			  WHERE received_at > now() - make_interval(days => $1)`, windowDays)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			out[s] = true
		}
		return rows.Err()
	})
	return out, err
}

// GetSettings returns the tenant's detection settings, or the seeded defaults when no row exists.
func (r *Repository) GetSettings(ctx context.Context, tenantID uuid.UUID) (Settings, error) {
	s := DefaultSettings()
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT fp_rate_threshold, min_feedback_sample, coverage_window_days, require_tests_for_production
			   FROM detection_settings WHERE tenant_id=$1`, tenantID).
			Scan(&s.FPRateThreshold, &s.MinFeedbackSample, &s.CoverageWindowDays, &s.RequireTestsForProduction)
		if e == pgx.ErrNoRows {
			return nil // keep defaults
		}
		return e
	})
	return s, err
}

// SetSettings upserts the tenant's detection settings.
func (r *Repository) SetSettings(ctx context.Context, tenantID uuid.UUID, s Settings) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO detection_settings
			   (tenant_id, fp_rate_threshold, min_feedback_sample, coverage_window_days, require_tests_for_production, updated_at)
			 VALUES ($1,$2,$3,$4,$5, now())
			 ON CONFLICT (tenant_id) DO UPDATE SET
			   fp_rate_threshold=$2, min_feedback_sample=$3, coverage_window_days=$4,
			   require_tests_for_production=$5, updated_at=now()`,
			tenantID, s.FPRateThreshold, s.MinFeedbackSample, s.CoverageWindowDays, s.RequireTestsForProduction)
		return err
	})
}
