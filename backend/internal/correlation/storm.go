package correlation

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// minStormThreshold floors the configurable storm threshold so a tenant can't set it to 0/1 and put
// itself permanently in storm mode (config-guardrail: overrides may only tighten within reason).
const minStormThreshold = 5

// Suppression is a maintenance-window / noise suppression rule (COR-007).
type Suppression struct {
	ID         uuid.UUID  `json:"id"`
	MatchType  string     `json:"match_type"` // entity | technique
	MatchValue string     `json:"match_value"`
	Reason     string     `json:"reason"`
	StartsAt   time.Time  `json:"starts_at"`
	EndsAt     *time.Time `json:"ends_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// StormStatus reports a tenant's alert-storm state (COR-008).
type StormStatus struct {
	ClustersLastHour int  `json:"clusters_last_hour"`
	Threshold        int  `json:"threshold"`
	InStorm          bool `json:"in_storm"`
}

// OverCorrelationMetrics measures how aggressively correlation is collapsing alerts (COR-010).
type OverCorrelationMetrics struct {
	Clusters         int     `json:"clusters"`
	TotalAlerts      int     `json:"total_alerts"`
	AlertsPerCluster float64 `json:"alerts_per_cluster"`
	LargestCluster   int     `json:"largest_cluster"`
	SingleAlertPct   float64 `json:"single_alert_pct"`

	singleAlertClusters int // scratch for the computation; not serialized
}

// ── Repository ──────────────────────────────────────────────────────────────────────────────────────

func (r *Repository) insertSuppression(ctx context.Context, tenantID uuid.UUID, s *Suppression, by uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO correlation_suppressions (id, tenant_id, match_type, match_value, reason, starts_at, ends_at, created_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`,
			s.ID, tenantID, s.MatchType, s.MatchValue, s.Reason, s.StartsAt, s.EndsAt, by,
		).Scan(&s.CreatedAt)
	})
}

func (r *Repository) listSuppressions(ctx context.Context, tenantID uuid.UUID) ([]Suppression, error) {
	var out []Suppression
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, match_type, match_value, reason, starts_at, ends_at, created_at
			   FROM correlation_suppressions ORDER BY created_at DESC LIMIT 200`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s Suppression
			if err := rows.Scan(&s.ID, &s.MatchType, &s.MatchValue, &s.Reason, &s.StartsAt, &s.EndsAt, &s.CreatedAt); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

func (r *Repository) deleteSuppression(ctx context.Context, tenantID, id uuid.UUID) (bool, error) {
	applied := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM correlation_suppressions WHERE id=$1`, id)
		if err != nil {
			return err
		}
		applied = ct.RowsAffected() == 1
		return nil
	})
	return applied, err
}

// activeSuppressionFor returns the reason of an ACTIVE suppression matching the entity or any of the
// techniques (now within [starts_at, ends_at)), or "" if none. One query using ANY for techniques.
func (r *Repository) activeSuppressionFor(ctx context.Context, tenantID uuid.UUID, entity string, techniques []string) (string, error) {
	reason := ""
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT reason FROM correlation_suppressions
			  WHERE starts_at <= now() AND (ends_at IS NULL OR ends_at > now())
			    AND ( (match_type='entity' AND match_value=$1)
			       OR (match_type='technique' AND match_value = ANY($2::text[])) )
			  ORDER BY created_at DESC LIMIT 1`, entity, techniques).Scan(&reason)
	})
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return reason, err
}

func (r *Repository) markSuppressed(ctx context.Context, tenantID, id uuid.UUID, reason string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE correlations SET suppressed=true, suppression_reason=$2 WHERE id=$1`, id, reason)
		return err
	})
}

// stormThreshold reads the tenant's configured storm threshold (floored), defaulting when no policy row.
func (r *Repository) stormThreshold(ctx context.Context, tenantID uuid.UUID) (int, error) {
	th := 25
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT storm_cluster_threshold FROM correlation_policies WHERE tenant_id=$1`, tenantID).Scan(&th)
		if e == pgx.ErrNoRows {
			return nil
		}
		return e
	})
	if err != nil {
		return 25, err
	}
	if th < minStormThreshold {
		th = minStormThreshold
	}
	return th, nil
}

// countRecentClusters counts PROMOTABLE clusters opened since `since` — those with enough corroboration
// to auto-open an incident (alert_count >= MinAlertsForPromotion). Round-5 H4: single-alert clusters
// (which can never auto-promote) are excluded, so a noise flood across many distinct entities cannot
// trip storm mode with clusters that were never going to open incidents anyway.
func (r *Repository) countRecentClusters(ctx context.Context, tenantID uuid.UUID, since time.Time) (int, error) {
	n := 0
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM correlations WHERE created_at >= $1 AND alert_count >= $2`,
			since, MinAlertsForPromotion).Scan(&n)
	})
	return n, err
}

func (r *Repository) overCorrelation(ctx context.Context, tenantID uuid.UUID) (OverCorrelationMetrics, error) {
	var m OverCorrelationMetrics
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*),
			        COALESCE(sum(alert_count),0),
			        COALESCE(max(alert_count),0),
			        COALESCE(count(*) FILTER (WHERE alert_count <= 1),0)
			   FROM correlations`).Scan(&m.Clusters, &m.TotalAlerts, &m.LargestCluster, &m.singleAlertClusters)
	})
	if err != nil {
		return m, err
	}
	if m.Clusters > 0 {
		m.AlertsPerCluster = float64(m.TotalAlerts) / float64(m.Clusters)
		m.SingleAlertPct = float64(m.singleAlertClusters) / float64(m.Clusters) * 100
	}
	return m, nil
}

// ── Service ─────────────────────────────────────────────────────────────────────────────────────────

// SuppressionInput creates a suppression / maintenance window (COR-007).
type SuppressionInput struct {
	MatchType  string     `json:"match_type"` // entity | technique
	MatchValue string     `json:"match_value"`
	Reason     string     `json:"reason"`
	StartsAt   *time.Time `json:"starts_at"`
	EndsAt     *time.Time `json:"ends_at"`
}

// CreateSuppression adds a suppression rule.
func (s *Service) CreateSuppression(ctx context.Context, tenantID uuid.UUID, by uuid.UUID, in SuppressionInput) (*Suppression, error) {
	if in.MatchType != "entity" && in.MatchType != "technique" {
		return nil, httpx.ErrBadRequest("match_type must be entity or technique")
	}
	if in.MatchValue == "" {
		return nil, httpx.ErrBadRequest("match_value is required")
	}
	if in.EndsAt != nil && in.StartsAt != nil && !in.EndsAt.After(*in.StartsAt) {
		return nil, httpx.ErrBadRequest("ends_at must be after starts_at")
	}
	sup := &Suppression{ID: uuid.New(), MatchType: in.MatchType, MatchValue: in.MatchValue, Reason: in.Reason, EndsAt: in.EndsAt}
	sup.StartsAt = time.Now()
	if in.StartsAt != nil {
		sup.StartsAt = *in.StartsAt
	}
	if err := s.repo.insertSuppression(ctx, tenantID, sup, by); err != nil {
		return nil, httpx.ErrInternal("could not create suppression")
	}
	return sup, nil
}

// ListSuppressions returns a tenant's suppression rules.
func (s *Service) ListSuppressions(ctx context.Context, tenantID uuid.UUID) ([]Suppression, error) {
	return s.repo.listSuppressions(ctx, tenantID)
}

// DeleteSuppression removes a suppression rule.
func (s *Service) DeleteSuppression(ctx context.Context, tenantID, id uuid.UUID) error {
	applied, err := s.repo.deleteSuppression(ctx, tenantID, id)
	if err != nil {
		return httpx.ErrInternal("could not delete suppression")
	}
	if !applied {
		return httpx.ErrNotFound("suppression not found")
	}
	return nil
}

// Storm returns the tenant's current alert-storm status (COR-008).
func (s *Service) Storm(ctx context.Context, tenantID uuid.UUID) (StormStatus, error) {
	th, err := s.repo.stormThreshold(ctx, tenantID)
	if err != nil {
		return StormStatus{}, httpx.ErrInternal("could not read storm policy")
	}
	n, err := s.repo.countRecentClusters(ctx, tenantID, time.Now().Add(-time.Hour))
	if err != nil {
		return StormStatus{}, httpx.ErrInternal("could not count clusters")
	}
	return StormStatus{ClustersLastHour: n, Threshold: th, InStorm: n >= th}, nil
}

// OverCorrelation returns the over-correlation metrics for a tenant (COR-010).
func (s *Service) OverCorrelation(ctx context.Context, tenantID uuid.UUID) (OverCorrelationMetrics, error) {
	m, err := s.repo.overCorrelation(ctx, tenantID)
	if err != nil {
		return m, httpx.ErrInternal("could not compute metrics")
	}
	return m, nil
}
