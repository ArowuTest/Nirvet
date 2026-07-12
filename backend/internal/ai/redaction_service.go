package ai

// §6.12 #188 HEAVY-1 — redaction config service. Resolves the effective per-tenant policy + composes the ordered
// pattern set (built-in floor + config-extensible DB patterns), and provides the tenant-admin management surface.
// Every read is fail-safe toward MASKING: a missing/broken policy resolves to the balanced default, and a pattern
// row that won't compile is skipped (the built-in floor still masks) — a config problem never egresses cleartext.

import (
	"context"
	"regexp"
	"sync"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// maxCustomPatterns bounds the DB pattern set a single tenant can add (egress-cost + ReDoS-surface bound).
const maxCustomPatterns = 32

// RedactionService loads redaction config and manages the tenant-admin surface.
type RedactionService struct {
	db    *database.DB
	cache sync.Map // regex string → *regexp.Regexp (compiled once, reused)
}

// NewRedactionService builds the service.
func NewRedactionService(db *database.DB) *RedactionService { return &RedactionService{db: db} }

// ResolvePolicy returns the tenant's effective policy (own row wins, else the global default). Any error → the
// fail-safe balanced default (mask); never cleartext.
func (s *RedactionService) ResolvePolicy(ctx context.Context, tenantID uuid.UUID) RedactionPolicy {
	pol := defaultRedactionPolicy()
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var enabled bool
		var mode string
		// own row (tenant_id=$1) sorts before the global (NULL) row via NULLS LAST → own wins.
		err := tx.QueryRow(ctx,
			`SELECT enabled, mode FROM ai_redaction_policy
			  WHERE tenant_id = $1 OR tenant_id IS NULL
			  ORDER BY tenant_id NULLS LAST LIMIT 1`, tenantID).Scan(&enabled, &mode)
		if err == nil && (mode == RedactBalanced || mode == RedactStrict || mode == RedactOff) {
			pol = RedactionPolicy{Enabled: enabled, Mode: mode}
		}
		return nil // swallow: fail-safe default already set
	})
	return pol
}

// Patterns composes the ordered masking set: built-in specific ++ config patterns (global + tenant own, enabled)
// ++ built-in broad. A config row that fails to compile is skipped (the floor still masks). Fail-safe: on any DB
// error the built-in floor alone is returned.
func (s *RedactionService) Patterns(ctx context.Context, tenantID uuid.UUID) []CompiledPattern {
	out := builtinSpecific()
	custom := make([]CompiledPattern, 0, 8)
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT regex, placeholder FROM ai_redaction_pattern
			  WHERE (tenant_id = $1 OR tenant_id IS NULL) AND enabled = true
			  ORDER BY created_at LIMIT $2`, tenantID, maxCustomPatterns)
		if err != nil {
			return nil // fail-safe: floor only
		}
		defer rows.Close()
		for rows.Next() {
			var rx, ph string
			if rows.Scan(&rx, &ph) != nil {
				continue
			}
			re := s.compiled(rx)
			if re == nil {
				continue // un-compilable row skipped — floor still applies
			}
			custom = append(custom, CompiledPattern{Placeholder: ph, Re: re})
		}
		return nil
	})
	out = append(out, custom...)
	return append(out, builtinBroad()...)
}

// compiled returns a cached compiled regex, or nil if it won't compile.
func (s *RedactionService) compiled(rx string) *regexp.Regexp {
	if v, ok := s.cache.Load(rx); ok {
		if re, ok := v.(*regexp.Regexp); ok {
			return re
		}
		return nil
	}
	re, err := regexp.Compile(rx)
	if err != nil {
		s.cache.Store(rx, (*regexp.Regexp)(nil))
		return nil
	}
	s.cache.Store(rx, re)
	return re
}

// ── tenant-admin management surface ───────────────────────────────────────────────────────────────────────────

// Policy is the tenant-facing policy view.
type Policy struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
}

// GetPolicy returns the tenant's effective policy for display.
func (s *RedactionService) GetPolicy(ctx context.Context, p auth.Principal) Policy {
	pol := s.ResolvePolicy(ctx, p.TenantID)
	return Policy{Enabled: pol.Enabled, Mode: pol.Mode}
}

// SetPolicy upserts the tenant's own policy row (never the global default). Audited.
func (s *RedactionService) SetPolicy(ctx context.Context, p auth.Principal, enabled bool, mode string) (Policy, error) {
	if mode != RedactBalanced && mode != RedactStrict && mode != RedactOff {
		return Policy{}, httpx.ErrBadRequest("mode must be balanced, strict, or off")
	}
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			`INSERT INTO ai_redaction_policy (tenant_id, enabled, mode) VALUES ($1,$2,$3)
			 ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid))
			 DO UPDATE SET enabled = EXCLUDED.enabled, mode = EXCLUDED.mode, updated_at = now()`,
			p.TenantID, enabled, mode); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "ai.redaction.set_policy",
			Target: "tenant:" + p.TenantID.String(), Metadata: map[string]any{"enabled": enabled, "mode": mode},
		})
	})
	if err != nil {
		return Policy{}, err
	}
	return Policy{Enabled: enabled, Mode: mode}, nil
}

// PatternView is a tenant-facing pattern row (own patterns only — global patterns are read-only platform config).
type PatternView struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Regex       string    `json:"regex"`
	Placeholder string    `json:"placeholder"`
	Enabled     bool      `json:"enabled"`
	Global      bool      `json:"global"`
}

var phRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}$`)

// ListPatterns returns the tenant's own patterns plus the global ones (global flagged, read-only).
func (s *RedactionService) ListPatterns(ctx context.Context, p auth.Principal) ([]PatternView, error) {
	var out []PatternView
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, name, regex, placeholder, enabled, tenant_id IS NULL
			   FROM ai_redaction_pattern WHERE tenant_id = $1 OR tenant_id IS NULL ORDER BY created_at`, p.TenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v PatternView
			if e := rows.Scan(&v.ID, &v.Name, &v.Regex, &v.Placeholder, &v.Enabled, &v.Global); e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

// AddPattern validates + compiles a new tenant-own pattern and inserts it (config-extensible masking without a code
// change). Rejects an un-compilable/oversized regex, a bad placeholder, or exceeding the per-tenant cap. Audited.
func (s *RedactionService) AddPattern(ctx context.Context, p auth.Principal, name, rx, placeholder string) (uuid.UUID, error) {
	if name == "" || len(name) > 64 {
		return uuid.Nil, httpx.ErrBadRequest("name is required (≤64 chars)")
	}
	if len(rx) == 0 || len(rx) > 512 {
		return uuid.Nil, httpx.ErrBadRequest("regex must be 1..512 chars")
	}
	if _, err := regexp.Compile(rx); err != nil {
		return uuid.Nil, httpx.ErrBadRequest("regex does not compile: " + err.Error())
	}
	if !phRe.MatchString(placeholder) {
		return uuid.Nil, httpx.ErrBadRequest("placeholder must match ^[A-Z][A-Z0-9_]{0,31}$")
	}
	var id uuid.UUID
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var n int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM ai_redaction_pattern WHERE tenant_id = $1`, p.TenantID).Scan(&n); e != nil {
			return e
		}
		if n >= maxCustomPatterns {
			return httpx.ErrBadRequest("per-tenant pattern limit reached")
		}
		if e := tx.QueryRow(ctx,
			`INSERT INTO ai_redaction_pattern (tenant_id, name, regex, placeholder) VALUES ($1,$2,$3,$4) RETURNING id`,
			p.TenantID, name, rx, placeholder).Scan(&id); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "ai.redaction.add_pattern",
			Target: "pattern:" + id.String(), Metadata: map[string]any{"name": name, "placeholder": placeholder},
		})
	})
	return id, err
}

// DeletePattern removes a tenant-own pattern (RLS blocks touching a global row). Audited.
func (s *RedactionService) DeletePattern(ctx context.Context, p auth.Principal, id uuid.UUID) error {
	return s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `DELETE FROM ai_redaction_pattern WHERE id = $1 AND tenant_id = $2`, id, p.TenantID)
		if e != nil {
			return e
		}
		if ct.RowsAffected() == 0 {
			return httpx.ErrNotFound("pattern not found")
		}
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "ai.redaction.delete_pattern", Target: "pattern:" + id.String(),
		})
	})
}
