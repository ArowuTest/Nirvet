// Package readmodel is the customer read-side RBAC / presentation-security layer (Slice A).
//
// THE CORE IDEA: the presentation boundary IS a security boundary, enforced server-side. Within the data a
// tenant is entitled to (RLS already isolates cross-tenant), different AUDIENCES — the provider SOC, the
// customer, and a government/anchor regulator — are entitled to very different VIEWS of the same incident or
// alert. A customer must never reach a provider-internal field by calling the API directly, regardless of what
// any UI shows.
//
// How the invariants are enforced (reviewer's 7 hard invariants):
//  1. Projections are POSITIVE ALLOWLISTS — distinct structs (CustomerIncidentView, RegulatorIncidentRollup, …)
//     that name ONLY the exposed fields. They are NOT the domain entity with `omit` tags. A denylist fails
//     OPEN (add a field to the entity and it silently appears); an allowlist fails CLOSED (a new entity field
//     is invisible until someone deliberately adds it to a projection). See projections.go + the reflection
//     tests in audience_test.go.
//  2. Audience resolution is the single chokepoint; a CI fence (scripts/check-audience-projection.sh) forbids a
//     customer-reachable read handler from returning a raw entity. Customer/regulator reads live only in this
//     package's handler and can only emit *View / *Rollup types.
//  5. RegulatorIncidentRollup / RegulatorAlertRollup are metadata-BY-CONSTRUCTION: they physically carry no
//     field that can hold incident content or PII (counts / categories / SLA only), and the regulator query
//     AGGREGATES over a grant-scoped tenant set — it never selects content rows.
//
// This package owns no table; it composes over the existing incident/alert/posture stores and their RLS.
package readmodel

import "github.com/ArowuTest/nirvet/internal/platform/auth"

// Audience is the read-scoping class a principal resolves to. The zero value is AudienceNone (fail-closed): an
// unclassified principal gets NO view, never a permissive default.
type Audience int

const (
	// AudienceNone is the fail-closed zero value — no read view. A principal that resolves here is denied.
	AudienceNone Audience = iota
	// AudienceRegulator is the most restrictive CONTENT class: metadata/aggregates only, grant-scoped.
	AudienceRegulator
	// AudienceCustomer sees their own tenant's incidents/alerts as finished work-products (redacted projection).
	AudienceCustomer
	// AudienceProvider is the full operational SOC view. Provider handlers (not this package) serve it.
	AudienceProvider
)

func (a Audience) String() string {
	switch a {
	case AudienceRegulator:
		return "regulator"
	case AudienceCustomer:
		return "customer"
	case AudienceProvider:
		return "provider"
	default:
		return "none"
	}
}

// Resolve classifies an authenticated principal into exactly one audience. It reads ONLY the principal's role
// (the actual data SCOPE for a regulator is resolved separately and fail-closed from the oversight grant
// tables — a regulator with no grant sees an empty rollup). Unknown/unhandled roles fall through to
// AudienceNone so a new role can never silently inherit a permissive view.
func Resolve(p auth.Principal) Audience {
	if auth.IsProviderRole(p.Role) {
		return AudienceProvider
	}
	switch p.Role {
	case auth.RoleCustomerAdmin, auth.RoleCustomerViewer:
		return AudienceCustomer
	case auth.RoleOrgSubAdmin, auth.RolePayer:
		return AudienceRegulator
	default:
		return AudienceNone
	}
}
