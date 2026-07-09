package soar

// §6.11 slice B — the destructive-action safety gate (pure decision) + its config types. The gate runs
// in Phase A of the two-phase model, AFTER authority-to-act + four-eyes have already permitted the step.
// It decides whether a permitted connector action executes for real, is dry-run, is withheld, or is
// downgraded to human confirmation — and every non-live outcome carries a reason (MUST-4: a withhold is
// never silent). Precedence (each dominates the ones below it):
//
//	kill-switch (global)  → withhold      -- absolute emergency stop, even in dry-run
//	not enabled/dry-run   → withhold      -- a tenant with neither destructive-enabled nor dry-run does nothing
//	not idempotent/rev.   → manual        -- MUST-1: can't safely auto-run → force human confirm (reported even in dry-run)
//	rate budget exhausted → withhold      -- MUST bound blast radius (reported even in dry-run)
//	dry-run (global/tenant)→ dry-run       -- full gate evaluated, no real effect
//	otherwise             → live
type gateOutcome int

const (
	gateLive     gateOutcome = iota // execute the real connector effect
	gateDryRun                      // full gate ran; make NO real effect, record dry_run
	gateWithhold                    // blocked (kill-switch/disabled/rate) — audited + surfaced, no effect
	gateManual                      // cannot auto-run safely — routed to human confirmation
)

// gateInputs are the already-fetched facts the pure gate decides on (no I/O here, so it is unit-testable).
type gateInputs struct {
	killSwitch     bool   // global platform kill-switch engaged
	platformDryRun bool   // global dry-run
	tenantEnabled  bool   // soar_settings.destructive_enabled
	tenantDryRun   bool   // soar_settings.dry_run
	canAuto        bool   // canAutoRun() — idempotent/precheck (+ reversible for Class3+)
	canAutoReason  string // why not, when canAuto is false
	rateRemaining  int    // remaining budget this hour for the action's risk class
}

// evaluateGate applies the precedence above. Returns the outcome and a reason for every non-live result.
func evaluateGate(in gateInputs) (gateOutcome, string) {
	if in.killSwitch {
		return gateWithhold, "global kill-switch engaged"
	}
	// A tenant validates the path with dry-run BEFORE enabling, so dry-run satisfies the enablement gate;
	// a tenant with neither enabled nor any dry-run performs no destructive action.
	if !in.tenantEnabled && !in.tenantDryRun && !in.platformDryRun {
		return gateWithhold, "destructive actions are not enabled for this tenant"
	}
	if !in.canAuto {
		return gateManual, in.canAutoReason
	}
	if in.rateRemaining <= 0 {
		return gateWithhold, "destructive-action rate limit exhausted for this hour"
	}
	if in.platformDryRun || in.tenantDryRun {
		return gateDryRun, "dry-run mode: no real effect"
	}
	return gateLive, ""
}

// SoarSettings is the per-tenant destructive-action config (tighten-only; destructive OFF by default).
type SoarSettings struct {
	DestructiveEnabled bool `json:"destructive_enabled"`
	DryRun             bool `json:"dry_run"`
	MaxClass3PerHour   int  `json:"max_class3_per_hour"`
	MaxClass4PerHour   int  `json:"max_class4_per_hour"`
}

// DefaultSoarSettings is returned when a tenant has no soar_settings row.
func DefaultSoarSettings() SoarSettings {
	return SoarSettings{DestructiveEnabled: false, DryRun: false, MaxClass3PerHour: 10, MaxClass4PerHour: 0}
}

// PlatformFlags is the global kill-switch + dry-run + reconciler thresholds. ConfirmationGraceSecs delays
// the first confirmation poll after submit; ConfirmationStallSecs bounds how long an action may stay
// non-terminal before it is surfaced as stalled (config-first, seeded defaults in soar_platform).
type PlatformFlags struct {
	KillSwitch            bool `json:"kill_switch"`
	DryRun                bool `json:"dry_run"`
	ConfirmationGraceSecs int  `json:"confirmation_grace_secs"`
	ConfirmationStallSecs int  `json:"confirmation_stall_secs"`
}

// rateCapFor returns the per-hour destructive-action cap for a risk class (0 = none allowed).
func (s SoarSettings) rateCapFor(risk RiskClass) int {
	switch risk {
	case RiskHigh:
		return s.MaxClass3PerHour
	case RiskBusinessCritical:
		return s.MaxClass4PerHour
	default:
		return 1 << 30 // lower classes are not rate-capped by the destructive limiter
	}
}
