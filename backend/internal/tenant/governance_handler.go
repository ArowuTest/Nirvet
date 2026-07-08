package tenant

// HTTP handlers for tenant profile & governance (SRS §6.1). Routes are role-gated in main
// (platform_admin + customer_admin); a customer_admin may only manage their OWN tenant,
// enforced here by scoped().

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// scoped resolves the target tenant from the path and enforces tenant scope: a platform_admin
// may target any tenant; anyone else (customer_admin) only their own. Returns ok=false and
// writes the error response when denied.
func (h *Handler) scoped(w http.ResponseWriter, r *http.Request) (auth.Principal, uuid.UUID, bool) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid tenant id"))
		return p, uuid.Nil, false
	}
	if p.Role != auth.RolePlatformAdmin && p.TenantID != id {
		httpx.Error(w, httpx.ErrForbidden("cannot manage another tenant"))
		return p, uuid.Nil, false
	}
	return p, id, true
}

// GetProfile handles GET /admin/tenants/{id}/profile.
func (h *Handler) GetProfile(w http.ResponseWriter, r *http.Request) {
	_, id, ok := h.scoped(w, r)
	if !ok {
		return
	}
	prof, err := h.svc.GetProfile(r.Context(), id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, prof)
}

// UpdateProfile handles PUT /admin/tenants/{id}/profile.
func (h *Handler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	p, id, ok := h.scoped(w, r)
	if !ok {
		return
	}
	var in ProfileInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	prof, err := h.svc.UpdateProfile(r.Context(), p, id, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, prof)
}

// SetStatus handles POST /admin/tenants/{id}/status.
func (h *Handler) SetStatus(w http.ResponseWriter, r *http.Request) {
	p, id, ok := h.scoped(w, r)
	if !ok {
		return
	}
	var in struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	t, err := h.svc.SetStatus(r.Context(), p, id, Status(in.Status), in.Reason)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, t)
}

// ListEscalation handles GET /admin/tenants/{id}/escalation-contacts.
func (h *Handler) ListEscalation(w http.ResponseWriter, r *http.Request) {
	_, id, ok := h.scoped(w, r)
	if !ok {
		return
	}
	cs, err := h.svc.ListEscalationContacts(r.Context(), id)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list escalation contacts"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"contacts": cs})
}

// AddEscalation handles POST /admin/tenants/{id}/escalation-contacts.
func (h *Handler) AddEscalation(w http.ResponseWriter, r *http.Request) {
	p, id, ok := h.scoped(w, r)
	if !ok {
		return
	}
	var in EscalationInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	c, err := h.svc.AddEscalationContact(r.Context(), p, id, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, c)
}

// DeleteEscalation handles DELETE /admin/tenants/{id}/escalation-contacts/{cid}.
func (h *Handler) DeleteEscalation(w http.ResponseWriter, r *http.Request) {
	p, id, ok := h.scoped(w, r)
	if !ok {
		return
	}
	cid, err := uuid.Parse(r.PathValue("cid"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid contact id"))
		return
	}
	if err := h.svc.DeleteEscalationContact(r.Context(), p, id, cid); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ListAuthority handles GET /admin/tenants/{id}/authority-policies.
func (h *Handler) ListAuthority(w http.ResponseWriter, r *http.Request) {
	_, id, ok := h.scoped(w, r)
	if !ok {
		return
	}
	ps, err := h.svc.ListAuthorityPolicies(r.Context(), id)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list authority policies"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"policies": ps})
}

// SetAuthority handles PUT /admin/tenants/{id}/authority-policies (upsert by action_type).
func (h *Handler) SetAuthority(w http.ResponseWriter, r *http.Request) {
	p, id, ok := h.scoped(w, r)
	if !ok {
		return
	}
	var in AuthorityInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	ap, err := h.svc.SetAuthorityPolicy(r.Context(), p, id, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, ap)
}

// ListHistory handles GET /admin/tenants/{id}/history.
func (h *Handler) ListHistory(w http.ResponseWriter, r *http.Request) {
	_, id, ok := h.scoped(w, r)
	if !ok {
		return
	}
	hs, err := h.svc.ListHistory(r.Context(), id)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list change history"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"history": hs})
}
