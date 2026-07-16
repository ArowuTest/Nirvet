// Package platformadmin is §6.18 platform administration: feature flags with a code-owned safety classification,
// immutable config audit, tenant lifecycle, and maintenance windows. This file is the CODE-OWNED flag registry —
// the safety class of a flag is decided HERE, never by an admin editing a row, so an admin cannot reclassify a
// protected flag to bypass its guard (the config-ization-without-guardrails lesson).
package platformadmin

// SafetyClass ranks how freely a feature flag may be flipped (the D5-analog for platform admin).
type SafetyClass string

const (
	ClassOpen      SafetyClass = "open"      // freely flippable by a platform-admin; audited
	ClassGuarded   SafetyClass = "guarded"   // security-relevant; needs reason + audit (also: flipping a protected flag MORE-secure)
	ClassProtected SafetyClass = "protected" // can disable a control; flipping LESS-secure needs senior+four-eyes+reason+time-box+HIGH alert
	ClassImmutable SafetyClass = "immutable" // never settable via config; resolved from code ONLY (a DB row is inert)
)

// FlagSpec is a registered flag: its class + its SECURE default (the value a missing/unknown flag resolves to).
type FlagSpec struct {
	Class         SafetyClass
	SecureDefault bool
	Desc          string
}

// registry is the authoritative flag catalog. Admins CANNOT edit it. Adding a flag = a code change + review —
// and, since J4, a code change that includes a READER. See flags_reachability_test.go, which fails the build for
// any non-immutable entry that nothing in production consults.
//
// J4 (reviewer, Jul 2026): this registry declared five SETTABLE flags and NOTHING read any of them —
// NewFlagResolver was never even constructed in main.go. The worst was
// `"soar.destructive_enabled": {ClassProtected, false, "SOAR real-containment master gate"}`: a platform admin
// could flip the containment master gate, with four-eyes ceremony and an audit trail, and change nothing. The
// real gates are soar_settings.DestructiveEnabled + plat.KillSwitch (sliceb_supervisor.go:115-116). That is
// protected_hosts inverted — that guard had a reader and no writer, so it silently ALLOWED; flags had a writer
// and no reader, so they silently REASSURED. A kill switch that lies in the reassuring direction costs exactly
// the minutes that matter.
//
// All five settable entries were deleted rather than wired, for two different reasons:
//
//   - soar.destructive_enabled / ai.egress_restricted — a real control already exists elsewhere (KillSwitch +
//     soar_settings; the #117 allowlist + the redaction floor). Wiring these would create a THIRD name for
//     "is containment armed" — which is the divergence defect (BUG-10, J3, criticality-vs-protected_*)
//     deliberately re-introduced inside the fix for its twin. Two names for one control is how each of those
//     began. A global flag that disables containment fleet-wide IS plat.KillSwitch, spelled differently.
//   - notify.delivery_enabled / connector.host_telemetry / ui.new_dashboard_beta — nothing anywhere implements
//     the control they name. They were promises, not switches. If the SOC wants a "stop all notifications"
//     kill switch it is a feature with a design, not a registry string.
//
// What remains is TRUE: these three controls are code-owned and configuration can never disable them. That is
// the same shape as ai/redaction.go's compiled floor — a control that works with zero configuration — stated
// here as a class so the SET path can refuse, and so an auditor can be shown the claim.
var registry = map[string]FlagSpec{
	// Immutable — security controls config must never be able to disable (resolved from code only, Reinf-A).
	// A DB row for these is inert BY DESIGN: the code is the reader, which is why they are exempt from the
	// reachability fence.
	"mfa.enforce":     {ClassImmutable, true, "MFA enforcement"},
	"rls.enforce":     {ClassImmutable, true, "row-level tenant isolation"},
	"audit.immutable": {ClassImmutable, true, "audit-log append-only"},
}

// Registered reports whether a key is in the catalog.
func Registered(key string) bool { _, ok := registry[key]; return ok }

// ClassOf returns a key's safety class. An UNREGISTERED key fails closed to `protected` (M-1) — a key nobody
// classified must be treated as if it could disable a control, so its flip carries the elevated envelope.
func ClassOf(key string) SafetyClass {
	if s, ok := registry[key]; ok {
		return s.Class
	}
	return ClassProtected
}

// SecureDefault returns the fail-safe value for a key. Unknown key → false (feature-off / conservative). A security
// control's secure default is ON; a risky feature's is OFF.
func SecureDefault(key string) bool {
	if s, ok := registry[key]; ok {
		return s.SecureDefault
	}
	return false
}

// IsImmutable reports whether a key is code-immutable (config can never set it; resolved from code).
func IsImmutable(key string) bool { return ClassOf(key) == ClassImmutable }
