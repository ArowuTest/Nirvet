package readmodel

// Slice B customer-audience read handlers: assets, vulnerabilities, compliance. Each is the SAME shape as the
// Slice A handlers — requireAudience(AudienceCustomer) chokepoint, read the caller's OWN tenant only, emit ONLY
// *View projections. They add no cross-tenant path. The CI fence (check-audience-projection.sh) requires these to
// be wired via custReadH.* on the customerRead chain, so a customer can reach nothing else.

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/compliance"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// ListAssets serves GET /customer/assets — the tenant's own asset inventory as redacted CustomerAssetViews.
func (h *Handler) ListAssets(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireAudience(w, r, AudienceCustomer)
	if !ok {
		return
	}
	if h.assets == nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"assets": []CustomerAssetView{}})
		return
	}
	as, err := h.assets.List(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not load assets"))
		return
	}
	out := make([]CustomerAssetView, 0, len(as))
	for _, a := range as {
		out = append(out, ProjectAssetForCustomer(a))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"assets": out})
}

// ListVulnerabilities serves GET /customer/vulnerabilities — exposure on the tenant's own estate as redacted
// CustomerVulnerabilityViews. No status/ref filter is exposed to the customer (they see their full posture);
// the underlying read is still RLS-scoped to their tenant.
func (h *Handler) ListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireAudience(w, r, AudienceCustomer)
	if !ok {
		return
	}
	if h.vulns == nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"vulnerabilities": []CustomerVulnerabilityView{}})
		return
	}
	vs, err := h.vulns.List(r.Context(), p.TenantID, "", "")
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not load vulnerabilities"))
		return
	}
	out := make([]CustomerVulnerabilityView, 0, len(vs))
	for _, v := range vs {
		out = append(out, ProjectVulnForCustomer(v))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"vulnerabilities": out})
}

// ListCompliance serves GET /customer/compliance — the tenant's own framework coverage posture. For each ENABLED
// framework the coverage is assessed and projected to a CustomerComplianceView (name/version/score/summary). A
// framework whose assessment errors is skipped rather than failing the whole response.
func (h *Handler) ListCompliance(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireAudience(w, r, AudienceCustomer)
	if !ok {
		return
	}
	if h.compl == nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"frameworks": []CustomerComplianceView{}})
		return
	}
	fws, err := h.compl.ListFrameworks(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not load compliance frameworks"))
		return
	}
	out := make([]CustomerComplianceView, 0, len(fws))
	for _, f := range fws {
		if !f.Enabled {
			continue
		}
		cov, err := h.compl.Assess(r.Context(), p.TenantID, f.Key)
		if err != nil {
			continue // one framework's assessment failing must not blank the whole posture
		}
		out = append(out, ProjectComplianceForCustomer(f, cov))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"frameworks": out})
}

// GetCompliance serves GET /customer/compliance/{key} — the drill-down for ONE framework: the function→control
// tree with per-control status + description, so the customer can see exactly which controls are the gaps. Only
// an ENABLED framework is resolvable (a disabled/unknown key is a 404 — existence is not revealed). Internal
// assessment metadata (source/note/evidence) is dropped at the projection boundary.
func (h *Handler) GetCompliance(w http.ResponseWriter, r *http.Request) {
	p, ok := h.requireAudience(w, r, AudienceCustomer)
	if !ok {
		return
	}
	if h.compl == nil {
		httpx.Error(w, httpx.ErrNotFound("framework not found"))
		return
	}
	key := r.PathValue("key")
	fws, err := h.compl.ListFrameworks(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not load compliance frameworks"))
		return
	}
	var fw *compliance.Framework
	for i := range fws {
		if fws[i].Key == key && fws[i].Enabled {
			fw = &fws[i]
			break
		}
	}
	if fw == nil {
		httpx.Error(w, httpx.ErrNotFound("framework not found"))
		return
	}
	cov, err := h.compl.Assess(r.Context(), p.TenantID, key)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not assess framework"))
		return
	}
	controls, err := h.compl.ListControls(r.Context(), p.TenantID, key)
	if err != nil {
		controls = nil // descriptions are best-effort; status tree still projects
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"framework": ProjectComplianceDetailForCustomer(*fw, cov, controls)})
}
