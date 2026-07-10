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

// registry is the authoritative flag catalog. Admins CANNOT edit it. Adding a flag = a code change + review.
var registry = map[string]FlagSpec{
	// Immutable — security controls config must never be able to disable (resolved from code only, Reinf-A).
	"mfa.enforce":     {ClassImmutable, true, "MFA enforcement"},
	"rls.enforce":     {ClassImmutable, true, "row-level tenant isolation"},
	"audit.immutable": {ClassImmutable, true, "audit-log append-only"},
	// Protected — CAN disable a control; secure default is the safe state.
	"soar.destructive_enabled": {ClassProtected, false, "SOAR real-containment master gate (per-tenant opt-in lives in soar_settings)"},
	"ai.egress_restricted":     {ClassProtected, true, "AI provider allowlist / residency restriction"},
	"notify.delivery_enabled":  {ClassProtected, true, "notification delivery (disabling risks a silent SOC)"},
	// Guarded / open — operational.
	"connector.host_telemetry": {ClassGuarded, false, "host-telemetry ingest (osquery/Wazuh)"},
	"ui.new_dashboard_beta":    {ClassOpen, false, "beta dashboard UI"},
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
