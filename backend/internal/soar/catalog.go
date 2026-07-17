package soar

// Action catalog (SRS §6.11 SOAR-002/004, §9.5). Config that maps each playbook step's action_key to
// a §9.5 risk class + an executor kind — admin-configurable data (global default + tenant override),
// not a code constant, so the risk class is no longer hardcoded in every playbook step's JSON.

import (
	"context"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ExecutorKind is how the engine dispatches an action.
type ExecutorKind string

const (
	ExecutorInternal  ExecutorKind = "internal"  // a Nirvet-native service (e.g. notify)
	ExecutorConnector ExecutorKind = "connector" // a source/EDR/IdP connector action
	ExecutorManual    ExecutorKind = "manual"    // a human/customer must act
)

var validExecutor = map[ExecutorKind]bool{ExecutorInternal: true, ExecutorConnector: true, ExecutorManual: true}

// ActionCatalog is one action's configuration.
type ActionCatalog struct {
	ID           uuid.UUID    `json:"id"`
	TenantID     *uuid.UUID   `json:"tenant_id,omitempty"` // nil = global default
	ActionKey    string       `json:"action_key"`
	Title        string       `json:"title"`
	RiskClass    RiskClass    `json:"risk_class"`
	Executor     ExecutorKind `json:"executor"`
	ConnectorKey string       `json:"connector_key"`
	Enabled      bool         `json:"enabled"`
	// FleetWide marks an action whose blast radius is the WHOLE TENANT (blocks a hash/IP/domain across every
	// endpoint), as opposed to a single host/user. It is a BREADTH gate axis INDEPENDENT of risk/reversibility:
	// a fleet-wide action is NEVER auto-eligible under ANY authority mode (the `!act.FleetWide` short-circuit in
	// runFor sits ABOVE the mode-dependent Allowed()), but stays approvable-and-runnable by a manager. Reversibility
	// is the wrong proxy for "safe to automate" at fleet scale — a reversible fleet-wide false positive is still a
	// fleet-wide outage. A tenant override may only RAISE this, never lower it (same clamp as RiskClass).
	FleetWide bool `json:"fleet_wide"`
}

// unknownAction is the fail-closed fallback for an action_key absent from the catalog: maximum risk
// (business_critical never auto-executes) so an unrecognised action can never run without approval.
func unknownAction(actionKey string) ActionCatalog {
	return ActionCatalog{ActionKey: actionKey, RiskClass: RiskBusinessCritical, Executor: ExecutorConnector, Enabled: true}
}

// =========================== repository ===========================

// resolveAction returns the effective catalog entry for an action_key. A tenant override may change
// the executor/connector and may RAISE the risk class, but NEVER lower it: the effective risk is
// max(seeded global class, tenant override class) — Round-4 M1, config may only tighten a safety
// guarantee, so an override cannot relabel a business_critical action as low to bypass the Class-4
// block. Loads both the global (authoritative seeded) row and the tenant override; RLS shows global
// + own only. Returns (unknownAction=business_critical, false) when nothing enabled matches (fail-closed).
func (r *Repository) resolveAction(ctx context.Context, tenantID uuid.UUID, actionKey string) (ActionCatalog, bool) {
	var global, override *ActionCatalog
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, action_key, title, risk_class, executor, connector_key, enabled, fleet_wide
			   FROM soar_action_catalog
			  WHERE action_key=$1 AND enabled = true AND (tenant_id = app_current_tenant() OR tenant_id IS NULL)`, actionKey)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a ActionCatalog
			if err := rows.Scan(&a.ID, &a.TenantID, &a.ActionKey, &a.Title, &a.RiskClass, &a.Executor, &a.ConnectorKey, &a.Enabled, &a.FleetWide); err != nil {
				return err
			}
			if a.TenantID == nil {
				g := a
				global = &g
			} else {
				o := a
				override = &o
			}
		}
		return rows.Err()
	})
	if err != nil || (global == nil && override == nil) {
		return unknownAction(actionKey), false
	}
	// The override (if any) supplies executor/connector; risk is clamped up to the seeded class.
	eff := global
	if override != nil {
		eff = override
		if global != nil && riskRank(global.RiskClass) > riskRank(override.RiskClass) {
			eff.RiskClass = global.RiskClass // override may only RAISE risk, never lower it
		}
		if global != nil && global.FleetWide {
			eff.FleetWide = true // override may only RAISE fleet_wide — a tenant can never un-mark a fleet-wide action
		}
	}
	return *eff, true
}

// resolveActionCatalogMap resolves the EFFECTIVE catalog entry for every action_key in ONE query (vs.
// resolveAction's one tx per key). It is the batch form used by the run-execution loops (runFor/executeRun/
// replan) to kill the per-step N+1: a playbook run resolves its whole catalog once, not per step. Semantics are
// identical to resolveAction — only enabled rows count; a tenant override supplies executor/connector but risk is
// clamped UP to the seeded global class (override may raise, never lower); a key absent from the map is resolved
// by the caller to unknownAction (business_critical, fail-closed). Callers MUST treat a missing key as
// unknownAction(key), exactly as resolveAction returns (unknownAction, false).
func (r *Repository) resolveActionCatalogMap(ctx context.Context, tenantID uuid.UUID) (map[string]ActionCatalog, error) {
	rows, err := r.listActionCatalog(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	globals := make(map[string]ActionCatalog)
	overrides := make(map[string]ActionCatalog)
	for _, a := range rows {
		if !a.Enabled {
			continue // resolveAction only considers enabled rows
		}
		if a.TenantID == nil {
			globals[a.ActionKey] = a
		} else {
			overrides[a.ActionKey] = a
		}
	}
	out := make(map[string]ActionCatalog, len(globals)+len(overrides))
	merge := func(key string) {
		g, hasG := globals[key]
		o, hasO := overrides[key]
		var eff ActionCatalog
		if hasO {
			eff = o
			if hasG && riskRank(g.RiskClass) > riskRank(o.RiskClass) {
				eff.RiskClass = g.RiskClass // override may only RAISE risk, never lower it
			}
			if hasG && g.FleetWide {
				eff.FleetWide = true // override may only RAISE fleet_wide (same tighten-only clamp as risk)
			}
		} else {
			eff = g
		}
		out[key] = eff
	}
	for k := range globals {
		merge(k)
	}
	for k := range overrides {
		if _, done := out[k]; !done {
			merge(k)
		}
	}
	return out, nil
}

// lookupAction resolves one key from a pre-built map, falling back to unknownAction (fail-closed) exactly as
// resolveAction does for an absent/disabled key — so callers using the batch map keep identical semantics.
func lookupAction(m map[string]ActionCatalog, key string) ActionCatalog {
	if a, ok := m[key]; ok {
		return a
	}
	return unknownAction(key)
}

func (r *Repository) listActionCatalog(ctx context.Context, tenantID uuid.UUID) ([]ActionCatalog, error) {
	var out []ActionCatalog
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, action_key, title, risk_class, executor, connector_key, enabled, fleet_wide
			   FROM soar_action_catalog
			  WHERE tenant_id = app_current_tenant() OR tenant_id IS NULL
			  ORDER BY action_key, tenant_id NULLS FIRST`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a ActionCatalog
			if err := rows.Scan(&a.ID, &a.TenantID, &a.ActionKey, &a.Title, &a.RiskClass, &a.Executor, &a.ConnectorKey, &a.Enabled, &a.FleetWide); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// upsertActionCatalog writes a tenant OVERRIDE row (never a global row — RLS WITH CHECK forbids it)
// and audits the change atomically.
func (r *Repository) upsertActionCatalog(ctx context.Context, p auth.Principal, tenantID uuid.UUID, a ActionCatalog) error {
	// Canonicalise casing (H-1): the actioner registry and the D5 guards must all see the same
	// lower-cased connector/action key, so a mis-cased override ("Defender") can't fire the actioner
	// while skipping the guard. The DB also enforces this with a CHECK (mig 0099).
	a.ConnectorKey = strings.ToLower(strings.TrimSpace(a.ConnectorKey))
	a.ActionKey = strings.ToLower(strings.TrimSpace(a.ActionKey))
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO soar_action_catalog (id, tenant_id, action_key, title, risk_class, executor, connector_key, enabled, fleet_wide)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			 ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), action_key)
			 DO UPDATE SET title=EXCLUDED.title, risk_class=EXCLUDED.risk_class, executor=EXCLUDED.executor,
			              connector_key=EXCLUDED.connector_key, enabled=EXCLUDED.enabled, fleet_wide=EXCLUDED.fleet_wide`,
			uuid.New(), tenantID, a.ActionKey, a.Title, a.RiskClass, a.Executor, a.ConnectorKey, a.Enabled, a.FleetWide); err != nil {
			return err
		}
		// A tenant may store fleet_wide=false here, but resolveAction/resolveActionCatalogMap clamp it back UP to the
		// seeded global's true — the override can only tighten, never un-mark a fleet-wide action.
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.action_catalog_set",
			Target: "action:" + a.ActionKey, Metadata: map[string]any{"risk_class": a.RiskClass, "executor": a.Executor, "fleet_wide": a.FleetWide}})
	})
}

// =========================== service ===========================

// ListActionCatalog returns the effective catalog for a tenant (global defaults + tenant overrides).
func (s *Service) ListActionCatalog(ctx context.Context, tenantID uuid.UUID) ([]ActionCatalog, error) {
	cs, err := s.repo.listActionCatalog(ctx, tenantID)
	if err != nil {
		return nil, httpx.ErrInternal("could not list action catalog")
	}
	return cs, nil
}

// ActionCatalogInput upserts a tenant override for an action.
type ActionCatalogInput struct {
	ActionKey    string       `json:"action_key"`
	Title        string       `json:"title"`
	RiskClass    RiskClass    `json:"risk_class"`
	Executor     ExecutorKind `json:"executor"`
	ConnectorKey string       `json:"connector_key"`
	Enabled      *bool        `json:"enabled"`
}

// SetActionCatalog upserts a tenant override for an action's class/executor, with validation + audit.
func (s *Service) SetActionCatalog(ctx context.Context, p auth.Principal, tenantID uuid.UUID, in ActionCatalogInput) (*ActionCatalog, error) {
	in.ActionKey = strings.TrimSpace(in.ActionKey)
	if in.ActionKey == "" {
		return nil, httpx.ErrBadRequest("action_key is required")
	}
	if !validRiskClass[in.RiskClass] {
		return nil, httpx.ErrBadRequest("invalid risk_class: informational|low|medium|high|business_critical")
	}
	if !validExecutor[in.Executor] {
		return nil, httpx.ErrBadRequest("invalid executor: internal|connector|manual")
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	a := ActionCatalog{TenantID: &tenantID, ActionKey: in.ActionKey, Title: in.Title,
		RiskClass: in.RiskClass, Executor: in.Executor, ConnectorKey: in.ConnectorKey, Enabled: enabled}
	if err := s.repo.upsertActionCatalog(ctx, p, tenantID, a); err != nil {
		return nil, httpx.ErrInternal("could not set action catalog")
	}
	return &a, nil
}
