package readmodel

import (
	"context"
	"net/http"
	"sort"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/compliance"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/vulnerability"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// IncidentReader is the narrow read surface the customer views need (satisfied by incident.Service).
type IncidentReader interface {
	Get(ctx context.Context, tenantID, id uuid.UUID) (*incident.Incident, error)
	Timeline(ctx context.Context, tenantID, id uuid.UUID) ([]incident.TimelineEntry, error)
	List(ctx context.Context, tenantID uuid.UUID) ([]incident.Incident, error)
}

// AlertReader is the narrow read surface for customer alert views (satisfied by alert.Service).
type AlertReader interface {
	List(ctx context.Context, tenantID uuid.UUID, status string) ([]alert.Alert, error)
}

// PolicyAPI is the disclosure-policy surface the handler needs (satisfied by *PolicyStore). An interface so
// handler tests can inject a fixed policy without a DB.
type PolicyAPI interface {
	Resolve(ctx context.Context, tenantID uuid.UUID) (DisclosurePolicy, error)
	SetPolicy(ctx context.Context, p auth.Principal, tenantID uuid.UUID, stages []string, discloseClosureNarrative bool) error
}

// RegulatorMetaReader is the metadata-only regulator read surface (satisfied by *RegulatorRepo).
type RegulatorMetaReader interface {
	IncidentMetaForTenants(ctx context.Context, tenantIDs []uuid.UUID) ([]IncidentMeta, error)
	AlertMetaForTenants(ctx context.Context, tenantIDs []uuid.UUID) ([]AlertMeta, error)
}

// AssetReader is the narrow customer-asset read surface (satisfied by asset.Service). Slice B.
type AssetReader interface {
	List(ctx context.Context, tenantID uuid.UUID) ([]asset.Asset, error)
}

// VulnReader is the narrow customer-vulnerability read surface (satisfied by vulnerability.Service). Slice B.
type VulnReader interface {
	List(ctx context.Context, tenantID uuid.UUID, status, ref string) ([]vulnerability.Vuln, error)
}

// ComplianceReader is the narrow customer-compliance read surface (satisfied by compliance.Service). Slice B.
type ComplianceReader interface {
	ListFrameworks(ctx context.Context, tenantID uuid.UUID) ([]compliance.Framework, error)
	Assess(ctx context.Context, tenantID uuid.UUID, frameworkKey string) (*compliance.Coverage, error)
	ListControls(ctx context.Context, tenantID uuid.UUID, frameworkKey string) ([]compliance.Control, error)
}

// Handler serves the customer- and regulator-audience read endpoints. It is THE projection chokepoint: it can
// only ever emit *View / *Rollup projection types — a raw incident/alert entity is never serialized here. A CI
// fence (scripts/check-audience-projection.sh) forbids a provider handler from being wired to a customer route,
// so customer traffic can reach only this handler.
type Handler struct {
	inc    IncidentReader
	alerts AlertReader
	policy PolicyAPI
	reg    RegulatorMetaReader
	scope  ScopeResolver
	assets AssetReader
	vulns  VulnReader
	compl  ComplianceReader
	db     *database.DB
}

// NewHandler builds the read-model handler. assets/vulns/compl are the Slice B customer read surfaces (may be nil
// in tests that exercise only the Slice A incident/alert paths — the Slice B handlers guard on nil).
func NewHandler(inc IncidentReader, alerts AlertReader, policy PolicyAPI, reg RegulatorMetaReader, scope ScopeResolver, assets AssetReader, vulns VulnReader, compl ComplianceReader, db *database.DB) *Handler {
	return &Handler{inc: inc, alerts: alerts, policy: policy, reg: reg, scope: scope, assets: assets, vulns: vulns, compl: compl, db: db}
}

// requireAudience resolves the principal and asserts it maps to the expected audience — a defense-in-depth
// chokepoint on top of the route's role gate (invariant 2). A mismatch is a 403; it never falls through to a
// more permissive view.
func (h *Handler) requireAudience(w http.ResponseWriter, r *http.Request, want Audience) (auth.Principal, bool) {
	p, _ := auth.PrincipalFrom(r.Context())
	if Resolve(p) != want {
		httpx.Error(w, httpx.ErrForbidden("not permitted for this view"))
		return p, false
	}
	return p, true
}

// ---- Customer audience ----

// ListIncidents serves GET /customer/incidents — the tenant's incidents that have reached a customer-visible
// stage, each as a redacted CustomerIncidentView (list items carry no timeline).
func (h *Handler) ListIncidents(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireAudience(w, r, AudienceCustomer)
	if !ok {
		return
	}
	pol, _ := h.policy.Resolve(r.Context(), p.TenantID) // fail-closed default on error
	all, err := h.inc.List(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not load incidents"))
		return
	}
	out := make([]CustomerIncidentView, 0, len(all))
	for _, inc := range all {
		if !pol.IncidentCustomerVisible(inc) {
			continue // row-gate: not at a customer-visible stage
		}
		out = append(out, ProjectIncidentForCustomer(inc, nil, pol))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"incidents": out})
}

// GetIncident serves GET /customer/incidents/{id} — one incident as a CustomerIncidentView with its
// customer-visible timeline. An incident not at a customer-visible stage returns 404 (existence not revealed).
func (h *Handler) GetIncident(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireAudience(w, r, AudienceCustomer)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	pol, _ := h.policy.Resolve(r.Context(), p.TenantID)
	inc, err := h.inc.Get(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, err) // already a typed 404/500 from the service
		return
	}
	if !pol.IncidentCustomerVisible(*inc) {
		httpx.Error(w, httpx.ErrNotFound("incident not found")) // do not reveal an internal-stage incident
		return
	}
	tl, err := h.inc.Timeline(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not load incident"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"incident": ProjectIncidentForCustomer(*inc, tl, pol)})
}

// ListAlerts serves GET /customer/alerts — the tenant's alerts as redacted CustomerAlertViews.
func (h *Handler) ListAlerts(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireAudience(w, r, AudienceCustomer)
	if !ok {
		return
	}
	als, err := h.alerts.List(r.Context(), p.TenantID, "")
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not load alerts"))
		return
	}
	out := make([]CustomerAlertView, 0, len(als))
	for _, a := range als {
		out = append(out, ProjectAlertForCustomer(a))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"alerts": out})
}

// ---- Regulator audience (grant-scoped, metadata-only aggregates) ----

// IncidentRollup serves GET /oversight/incidents-rollup — an aggregate incident count over the regulator's
// grant-scoped tenant set. Content never enters the app (metadata-only SD function). The cross-tenant read is
// audited under the reader's own tenant.
func (h *Handler) IncidentRollup(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireAudience(w, r, AudienceRegulator)
	if !ok {
		return
	}
	scope, err := h.scope.TenantScope(r.Context(), p)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not resolve oversight scope"))
		return
	}
	metas, err := h.reg.IncidentMetaForTenants(r.Context(), scope)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not load incident rollup"))
		return
	}
	h.auditOversightRead(r.Context(), p, "incidents", len(scope))
	httpx.JSON(w, http.StatusOK, BuildRegulatorIncidentRollup(metas, len(scope)))
}

// AlertRollup serves GET /oversight/alerts-rollup — an aggregate alert count over the grant-scoped tenant set.
func (h *Handler) AlertRollup(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireAudience(w, r, AudienceRegulator)
	if !ok {
		return
	}
	scope, err := h.scope.TenantScope(r.Context(), p)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not resolve oversight scope"))
		return
	}
	metas, err := h.reg.AlertMetaForTenants(r.Context(), scope)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not load alert rollup"))
		return
	}
	h.auditOversightRead(r.Context(), p, "alerts", len(scope))
	httpx.JSON(w, http.StatusOK, BuildRegulatorAlertRollup(metas, len(scope)))
}

// ---- Disclosure policy admin (operator-configures-per-customer; no-hardcoding rule) ----

// GetDisclosurePolicy serves GET /admin/tenants/{tenant_id}/disclosure-policy — the current (or fail-closed
// default) disclosure policy for a tenant. Provider-operator gated at the route.
func (h *Handler) GetDisclosurePolicy(w http.ResponseWriter, r *http.Request) {
	_, tenantID, ok := auth.ScopeToTenant(w, r, "tenant_id")
	if !ok {
		return
	}
	pol, _ := h.policy.Resolve(r.Context(), tenantID)
	stages := make([]string, 0, len(pol.CustomerVisibleStages))
	for s := range pol.CustomerVisibleStages {
		stages = append(stages, string(s))
	}
	sort.Strings(stages)
	httpx.JSON(w, http.StatusOK, map[string]any{
		"customer_visible_stages": stages, "disclose_closure_narrative": pol.DiscloseClosureNarrative,
	})
}

type setDisclosureReq struct {
	CustomerVisibleStages    []string `json:"customer_visible_stages"`
	DiscloseClosureNarrative bool     `json:"disclose_closure_narrative"`
}

// SetDisclosurePolicy serves PUT /admin/tenants/{tenant_id}/disclosure-policy — the PROVIDER operator configures
// what a customer tenant sees (a customer cannot self-widen; this route is operator-gated). Stages are validated
// against the closed lifecycle set and the change is audited.
func (h *Handler) SetDisclosurePolicy(w http.ResponseWriter, r *http.Request) {
	p, tenantID, ok := auth.ScopeToTenant(w, r, "tenant_id")
	if !ok {
		return
	}
	var req setDisclosureReq
	if err := httpx.Decode(r, &req); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.policy.SetPolicy(r.Context(), p, tenantID, req.CustomerVisibleStages, req.DiscloseClosureNarrative); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

// auditOversightRead records who ran a cross-tenant regulator rollup and how wide the scope was (mirrors
// posture.Fleet). Best-effort under the reader's own tenant context.
func (h *Handler) auditOversightRead(ctx context.Context, p auth.Principal, kind string, scopeN int) {
	if h.db == nil {
		return
	}
	_ = h.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "readmodel.oversight_rollup_read",
			Target: "oversight:" + kind, Metadata: map[string]any{"tenants_in_scope": scopeN},
		})
	})
}
