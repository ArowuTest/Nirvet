package compliance

import (
	"context"

	"github.com/google/uuid"
)

// Statuses. A control is met/partial/gap, or not_applicable (excluded from scoring).
const (
	StatusMet           = "met"
	StatusPartial       = "partial"
	StatusGap           = "gap"
	StatusNotApplicable = "not_applicable"
)

// signalResult is what a resolver returns for a control.
type signalResult struct {
	Status string
	Note   string
}

// resolver measures a live platform signal for a tenant. Resolvers are CODE (they inspect real state);
// the control→signal mapping that selects which resolver runs is DB config. Resolvers are honest: an
// unbuilt capability resolves to gap, never a fabricated "met".
type resolver func(ctx context.Context, r *Repository, tenantID uuid.UUID, cfg map[string]any) signalResult

// signals is the registry keyed by the control's auto_signal value.
var signals = map[string]resolver{
	// Platform-guaranteed capabilities (RLS isolation, credential vault, immutable audit, RBAC/authority):
	// present for every tenant by construction, so met — the note explains what backs it.
	"platform_capability": func(_ context.Context, _ *Repository, _ uuid.UUID, cfg map[string]any) signalResult {
		return signalResult{Status: StatusMet, Note: noteOf(cfg, "Platform capability present.")}
	},
	// Detection coverage: measures the TENANT's OWN posture (Round-5 M3) — the global seed catalogue
	// must not auto-satisfy a control for a tenant that authored zero rules.
	"detection_coverage": func(ctx context.Context, r *Repository, tid uuid.UUID, _ map[string]any) signalResult {
		return metIfPositive(ctx, r, tid, `SELECT count(*) FROM detection_rules WHERE enabled = true AND tenant_id = app_current_tenant()`,
			"enabled detection rule(s) in coverage", "no enabled tenant detection rules")
	},
	// Incident response: case-management capability is present platform-wide.
	"incident_response": func(_ context.Context, _ *Repository, _ uuid.UUID, _ map[string]any) signalResult {
		return signalResult{Status: StatusMet, Note: "Incident case management with SLA timers and escalation."}
	},
	// Response automation: met if the tenant has an enabled playbook (global or own), else partial (manual
	// response still available, automation not configured).
	"soar_automation": func(ctx context.Context, r *Repository, tid uuid.UUID, _ map[string]any) signalResult {
		n, err := r.count(ctx, tid, `SELECT count(*) FROM playbooks WHERE enabled = true AND tenant_id = app_current_tenant()`)
		if err != nil {
			return signalResult{Status: StatusGap, Note: "could not evaluate playbook coverage"}
		}
		if n > 0 {
			return signalResult{Status: StatusMet, Note: plural(n, "enabled playbook")}
		}
		return signalResult{Status: StatusPartial, Note: "no automated playbooks; manual response only"}
	},
	// Threat intelligence: met if any STIX object or watchlist indicator is visible (global feed + own).
	"threat_intel": func(ctx context.Context, r *Repository, tid uuid.UUID, _ map[string]any) signalResult {
		n, err := r.count(ctx, tid,
			`SELECT (SELECT count(*) FROM stix_objects WHERE NOT revoked AND tenant_id = app_current_tenant())
			      + (SELECT count(*) FROM threat_indicators WHERE tenant_id = app_current_tenant())`)
		if err != nil {
			return signalResult{Status: StatusGap, Note: "could not evaluate threat-intel coverage"}
		}
		if n > 0 {
			return signalResult{Status: StatusMet, Note: plural(n, "threat-intel object/indicator")}
		}
		return signalResult{Status: StatusGap, Note: "no threat intelligence loaded"}
	},
	// Asset inventory: per-tenant — gap until the tenant onboards assets.
	"asset_inventory": func(ctx context.Context, r *Repository, tid uuid.UUID, _ map[string]any) signalResult {
		return metIfPositive(ctx, r, tid, `SELECT count(*) FROM assets WHERE tenant_id = app_current_tenant()`,
			"asset(s) in inventory", "no assets inventoried")
	},
	// Explicitly-unbuilt capability → honest gap.
	"not_implemented": func(_ context.Context, _ *Repository, _ uuid.UUID, cfg map[string]any) signalResult {
		return signalResult{Status: StatusGap, Note: noteOf(cfg, "Not yet implemented in-platform.")}
	},
}

// resolveSignal runs the resolver named by a control's auto_signal. An empty signal is a rollup control
// (status computed from children, handled by the service). An unknown/manual signal → gap.
func resolveSignal(ctx context.Context, r *Repository, tenantID uuid.UUID, c Control) signalResult {
	fn, ok := signals[c.AutoSignal]
	if !ok {
		return signalResult{Status: StatusGap, Note: "awaiting manual assessment"}
	}
	return fn(ctx, r, tenantID, c.AutoConfig)
}

func metIfPositive(ctx context.Context, r *Repository, tid uuid.UUID, query, metNote, gapNote string) signalResult {
	n, err := r.count(ctx, tid, query)
	if err != nil {
		return signalResult{Status: StatusGap, Note: "could not evaluate: " + gapNote}
	}
	if n > 0 {
		return signalResult{Status: StatusMet, Note: itoa(n) + " " + metNote}
	}
	return signalResult{Status: StatusGap, Note: gapNote}
}

// scoreOf maps a status to its numeric score.
func scoreOf(status string) int {
	switch status {
	case StatusMet:
		return 100
	case StatusPartial:
		return 50
	default:
		return 0
	}
}

func noteOf(cfg map[string]any, def string) string {
	if cfg != nil {
		if n, ok := cfg["note"].(string); ok && n != "" {
			return n
		}
	}
	return def
}

func plural(n int, unit string) string {
	s := itoa(n) + " " + unit
	if n != 1 {
		s += "s"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
