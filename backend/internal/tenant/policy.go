package tenant

// Admin-configurable operational policy that was previously hardcoded as Go constants
// (Phase 0-D, owner no-hardcoding rule): incident SLA per-severity targets (§6.8) and the
// alert-correlation window/thresholds (§6.7). Each is a tenant-scoped, seeded-default DB row
// resolved at runtime via a narrow interface the consuming package defines (incident.SLAResolver,
// correlation.PolicyResolver). The consuming packages keep the same literals only as fail-safe
// fallbacks for when a resolver is unwired or a tenant somehow lacks a row.

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// policyCache memoises a tenant's SLA + correlation policy for a short TTL so the hot paths do
// NOT hit the DB on every call — correlation.Correlate resolves the policy once per alert, and
// SLA resolution runs on every incident open. Mirrors the threatintel enricher cache. A write
// (SetSLAPolicy / SetCorrelationPolicy) invalidates the affected tenant so changes take effect at
// once on the writing instance; other instances converge within the TTL (eventual consistency,
// same as the enricher). Cross-instance staleness of a window/threshold change is harmless.
type policyCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	sla  map[uuid.UUID]slaCacheEntry
	corr map[uuid.UUID]corrCacheEntry
}

type slaCacheEntry struct {
	bySeverity map[string][2]time.Duration // severity -> {ack, resolve}
	expires    time.Time
}

type corrCacheEntry struct {
	window           time.Duration
	promoteThreshold int
	minAlerts        int
	expires          time.Time
}

func newPolicyCache(ttl time.Duration) *policyCache {
	return &policyCache{ttl: ttl, sla: map[uuid.UUID]slaCacheEntry{}, corr: map[uuid.UUID]corrCacheEntry{}}
}

func (c *policyCache) invalidate(tenantID uuid.UUID) {
	c.mu.Lock()
	delete(c.sla, tenantID)
	delete(c.corr, tenantID)
	c.mu.Unlock()
}

// defaultSLASeconds is the single Go source of truth for the SLA defaults SeedGovernance writes
// for a new tenant: {ack, resolve} seconds per severity. Mirrors migration 0035's backfill and
// internal/incident/sla.go's fallback map — keep the three in sync.
var defaultSLASeconds = map[string][2]int{
	"critical":      {900, 14400},    // 15m ack / 4h resolve
	"high":          {1800, 28800},   // 30m ack / 8h resolve
	"medium":        {7200, 86400},   // 2h ack / 24h resolve
	"low":           {28800, 259200}, // 8h ack / 72h resolve
	"informational": {86400, 432000}, // 24h ack / 120h resolve
}

// Correlation seeded defaults (mirror internal/correlation/correlation.go's consts + migration).
const (
	defaultCorrelationWindowSeconds = 21600 // 6h
	defaultCorrelationPromote       = 70
	defaultCorrelationMinAlerts     = 2
)

// --- SLA policy (§6.8) ---

// SLAPolicy is a tenant's ack/resolve deadline for one severity (seconds).
type SLAPolicy struct {
	TenantID       uuid.UUID `json:"tenant_id"`
	Severity       string    `json:"severity"`
	AckSeconds     int       `json:"ack_seconds"`
	ResolveSeconds int       `json:"resolve_seconds"`
}

// SLAInput upserts one severity's SLA targets.
type SLAInput struct {
	Severity       string `json:"severity"`
	AckSeconds     int    `json:"ack_seconds"`
	ResolveSeconds int    `json:"resolve_seconds"`
}

// ResolveSLA returns the tenant's configured ack/resolve deadlines for a severity as durations,
// implementing incident.SLAResolver. Served from the per-tenant cache (one query per TTL, not one
// per call). On a missing/unknown severity it returns (0,0,nil) so the incident service falls back
// to its own default policy — never a zero-length SLA.
func (s *Service) ResolveSLA(ctx context.Context, tenantID uuid.UUID, severity string) (ack, resolve time.Duration, err error) {
	m, err := s.slaBySeverity(ctx, tenantID)
	if err != nil {
		return 0, 0, err
	}
	if d, ok := m[severity]; ok {
		return d[0], d[1], nil
	}
	return 0, 0, nil
}

// slaBySeverity returns the tenant's severity->{ack,resolve} map, cached for the policy-cache TTL
// and loaded in a single query on a miss (all five rows), so the per-incident hot path does not
// hit the DB every time.
func (s *Service) slaBySeverity(ctx context.Context, tenantID uuid.UUID) (map[string][2]time.Duration, error) {
	s.cache.mu.Lock()
	ent, ok := s.cache.sla[tenantID]
	s.cache.mu.Unlock()
	if ok && time.Now().Before(ent.expires) {
		return ent.bySeverity, nil
	}
	rows, err := s.repo.listSLA(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	m := make(map[string][2]time.Duration, len(rows))
	for _, p := range rows {
		m[p.Severity] = [2]time.Duration{
			time.Duration(p.AckSeconds) * time.Second,
			time.Duration(p.ResolveSeconds) * time.Second,
		}
	}
	s.cache.mu.Lock()
	s.cache.sla[tenantID] = slaCacheEntry{bySeverity: m, expires: time.Now().Add(s.cache.ttl)}
	s.cache.mu.Unlock()
	return m, nil
}

// ListSLAPolicies returns the tenant's SLA targets, seeding defaults if none exist yet (so the
// response is always the configurable default set, never empty).
func (s *Service) ListSLAPolicies(ctx context.Context, tenantID uuid.UUID) ([]SLAPolicy, error) {
	ps, err := s.repo.listSLA(ctx, tenantID)
	if err != nil {
		return nil, httpx.ErrInternal("could not list SLA policies")
	}
	if len(ps) == 0 {
		if serr := s.repo.SeedGovernance(ctx, tenantID); serr != nil {
			return nil, httpx.ErrInternal("could not initialise SLA policies")
		}
		if ps, err = s.repo.listSLA(ctx, tenantID); err != nil {
			return nil, httpx.ErrInternal("could not list SLA policies")
		}
	}
	return ps, nil
}

// SetSLAPolicy upserts one severity's ack/resolve targets, recording the change to the append-only
// history and audit log. Deadlines are validated (positive, resolve >= ack) so a config change can
// never disable an SLA or set resolve before ack.
func (s *Service) SetSLAPolicy(ctx context.Context, p auth.Principal, tenantID uuid.UUID, in SLAInput) (*SLAPolicy, error) {
	if !validSeverity[in.Severity] {
		return nil, httpx.ErrBadRequest("invalid severity: informational|low|medium|high|critical")
	}
	if in.AckSeconds <= 0 || in.ResolveSeconds <= 0 {
		return nil, httpx.ErrBadRequest("ack_seconds and resolve_seconds must be positive")
	}
	if in.ResolveSeconds < in.AckSeconds {
		return nil, httpx.ErrBadRequest("resolve_seconds must be >= ack_seconds")
	}
	pol := &SLAPolicy{TenantID: tenantID, Severity: in.Severity, AckSeconds: in.AckSeconds, ResolveSeconds: in.ResolveSeconds}
	err := s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			`INSERT INTO sla_policies (tenant_id, severity, ack_seconds, resolve_seconds)
			 VALUES ($1,$2,$3,$4)
			 ON CONFLICT (tenant_id, severity) DO UPDATE
			   SET ack_seconds=EXCLUDED.ack_seconds, resolve_seconds=EXCLUDED.resolve_seconds, updated_at=now()`,
			tenantID, in.Severity, in.AckSeconds, in.ResolveSeconds); e != nil {
			return e
		}
		newV := strconv.Itoa(in.AckSeconds) + "/" + strconv.Itoa(in.ResolveSeconds) + "s"
		if e := recordChange(ctx, tx, tenantID, p, "sla", in.Severity, "", newV); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "tenant.sla_set",
			Target: "tenant:" + tenantID.String(), Metadata: map[string]any{"severity": in.Severity, "ack_seconds": in.AckSeconds, "resolve_seconds": in.ResolveSeconds}})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not set SLA policy")
	}
	s.cache.invalidate(tenantID) // subsequent resolves see the new value immediately on this instance
	return pol, nil
}

// --- correlation policy (§6.7) ---

// CorrelationPolicy is a tenant's clustering window + auto-promotion thresholds.
type CorrelationPolicy struct {
	TenantID         uuid.UUID `json:"tenant_id"`
	WindowSeconds    int       `json:"window_seconds"`
	PromoteThreshold int       `json:"promote_threshold"`
	MinAlerts        int       `json:"min_alerts_for_promotion"`
}

// CorrelationInput upserts the tenant's correlation policy.
type CorrelationInput struct {
	WindowSeconds    int `json:"window_seconds"`
	PromoteThreshold int `json:"promote_threshold"`
	MinAlerts        int `json:"min_alerts_for_promotion"`
}

// ResolveCorrelationPolicy returns the tenant's correlation window + thresholds, implementing
// correlation.PolicyResolver. Served from the per-tenant cache (one query per TTL, not one per
// alert). On a missing row it returns the seeded defaults uncached (a transient pre-seed state;
// every real tenant is seeded at Create) — never a zero window, which would collapse clustering.
func (s *Service) ResolveCorrelationPolicy(ctx context.Context, tenantID uuid.UUID) (window time.Duration, promoteThreshold, minAlerts int, err error) {
	s.cache.mu.Lock()
	ent, ok := s.cache.corr[tenantID]
	s.cache.mu.Unlock()
	if ok && time.Now().Before(ent.expires) {
		return ent.window, ent.promoteThreshold, ent.minAlerts, nil
	}
	p, err := s.repo.getCorrelationPolicy(ctx, tenantID)
	if err == pgx.ErrNoRows {
		return time.Duration(defaultCorrelationWindowSeconds) * time.Second, defaultCorrelationPromote, defaultCorrelationMinAlerts, nil
	}
	if err != nil {
		return 0, 0, 0, err
	}
	w := time.Duration(p.WindowSeconds) * time.Second
	s.cache.mu.Lock()
	s.cache.corr[tenantID] = corrCacheEntry{window: w, promoteThreshold: p.PromoteThreshold, minAlerts: p.MinAlerts, expires: time.Now().Add(s.cache.ttl)}
	s.cache.mu.Unlock()
	return w, p.PromoteThreshold, p.MinAlerts, nil
}

// GetCorrelationPolicy returns the tenant's correlation policy, seeding the default row if none
// exists yet (so the response is always the configurable default, never empty).
func (s *Service) GetCorrelationPolicy(ctx context.Context, tenantID uuid.UUID) (*CorrelationPolicy, error) {
	p, err := s.repo.getCorrelationPolicy(ctx, tenantID)
	if err == pgx.ErrNoRows {
		if serr := s.repo.SeedGovernance(ctx, tenantID); serr != nil {
			return nil, httpx.ErrInternal("could not initialise correlation policy")
		}
		p, err = s.repo.getCorrelationPolicy(ctx, tenantID)
	}
	if err != nil {
		return nil, httpx.ErrInternal("could not load correlation policy")
	}
	return p, nil
}

// SetCorrelationPolicy upserts the tenant's correlation window + thresholds, recording the change
// to history + audit. Bounds are validated so a config change can never disable corroboration
// (min_alerts >= 1) or set an impossible threshold.
func (s *Service) SetCorrelationPolicy(ctx context.Context, p auth.Principal, tenantID uuid.UUID, in CorrelationInput) (*CorrelationPolicy, error) {
	if in.WindowSeconds <= 0 {
		return nil, httpx.ErrBadRequest("window_seconds must be positive")
	}
	if in.PromoteThreshold < 1 || in.PromoteThreshold > 100 {
		return nil, httpx.ErrBadRequest("promote_threshold must be between 1 and 100")
	}
	// Corroboration floor (Round-4 L2 / R2 M-A): auto-promotion requires >= 2 alerts so a single
	// crafted event can never spawn an incident. Config may tighten this (raise it) but not weaken it.
	if in.MinAlerts < 2 {
		return nil, httpx.ErrBadRequest("min_alerts_for_promotion must be >= 2 (anti-single-event-spam floor)")
	}
	pol := &CorrelationPolicy{TenantID: tenantID, WindowSeconds: in.WindowSeconds, PromoteThreshold: in.PromoteThreshold, MinAlerts: in.MinAlerts}
	err := s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			`INSERT INTO correlation_policies (tenant_id, window_seconds, promote_threshold, min_alerts_for_promotion)
			 VALUES ($1,$2,$3,$4)
			 ON CONFLICT (tenant_id) DO UPDATE
			   SET window_seconds=EXCLUDED.window_seconds, promote_threshold=EXCLUDED.promote_threshold,
			       min_alerts_for_promotion=EXCLUDED.min_alerts_for_promotion, updated_at=now()`,
			tenantID, in.WindowSeconds, in.PromoteThreshold, in.MinAlerts); e != nil {
			return e
		}
		newV := strconv.Itoa(in.WindowSeconds) + "s/th" + strconv.Itoa(in.PromoteThreshold) + "/min" + strconv.Itoa(in.MinAlerts)
		if e := recordChange(ctx, tx, tenantID, p, "correlation", "policy", "", newV); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "tenant.correlation_set",
			Target: "tenant:" + tenantID.String(), Metadata: map[string]any{"window_seconds": in.WindowSeconds, "promote_threshold": in.PromoteThreshold, "min_alerts_for_promotion": in.MinAlerts}})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not set correlation policy")
	}
	s.cache.invalidate(tenantID) // subsequent resolves see the new value immediately on this instance
	return pol, nil
}

// =========================== repository helpers ===========================

func (r *Repository) listSLA(ctx context.Context, tenantID uuid.UUID) ([]SLAPolicy, error) {
	var out []SLAPolicy
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id, severity, ack_seconds, resolve_seconds FROM sla_policies
			   ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p SLAPolicy
			if err := rows.Scan(&p.TenantID, &p.Severity, &p.AckSeconds, &p.ResolveSeconds); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

func (r *Repository) getCorrelationPolicy(ctx context.Context, tenantID uuid.UUID) (*CorrelationPolicy, error) {
	var p CorrelationPolicy
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id, window_seconds, promote_threshold, min_alerts_for_promotion
			   FROM correlation_policies WHERE tenant_id=$1`, tenantID).
			Scan(&p.TenantID, &p.WindowSeconds, &p.PromoteThreshold, &p.MinAlerts)
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}
