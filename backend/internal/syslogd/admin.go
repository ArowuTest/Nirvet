package syslogd

// Padmin source-provisioning surface: register/enable/disable/list/delete syslog sources. platform_admin-only
// (route-gated; the padmin chain's auditMut records each mutation — who provisioned/enabled/revoked a source).
// A registered source is DISABLED by default (secure default) — the listener rejects it until it is enabled.

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// AdminHandler is the padmin syslog-source management HTTP surface.
type AdminHandler struct{ store *SourceStore }

// NewAdminHandler wires the source-management handler.
func NewAdminHandler(store *SourceStore) *AdminHandler { return &AdminHandler{store: store} }

type createSourceReq struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Fingerprint string    `json:"cert_fingerprint"`
}

// Create handles POST /admin/syslog-sources — register a source (disabled by default).
func (h *AdminHandler) Create(w http.ResponseWriter, r *http.Request) {
	var in createSourceReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if in.TenantID == uuid.Nil || in.Fingerprint == "" {
		httpx.Error(w, httpx.ErrBadRequest("tenant_id and cert_fingerprint are required"))
		return
	}
	id, err := h.store.Create(r.Context(), in.TenantID, in.Name, in.Fingerprint)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not register source"))
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{"id": id, "enabled": false})
}

type setEnabledReq struct {
	Enabled bool `json:"enabled"`
}

// SetEnabled handles POST /admin/syslog-sources/{id}/enabled — enable or disable (revoke) a source.
func (h *AdminHandler) SetEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid source id"))
		return
	}
	var in setEnabledReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.store.SetEnabled(r.Context(), id, in.Enabled); err != nil {
		httpx.Error(w, httpx.ErrInternal("could not update source"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"id": id, "enabled": in.Enabled})
}

// Delete handles DELETE /admin/syslog-sources/{id}.
func (h *AdminHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid source id"))
		return
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		httpx.Error(w, httpx.ErrInternal("could not delete source"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// List handles GET /admin/syslog-sources.
func (h *AdminHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.store.List(r.Context())
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list sources"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"sources": rows, "count": len(rows)})
}
