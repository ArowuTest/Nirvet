package ingestion

// §6.5 slice A HTTP: normalization data-quality dashboard + settings (NORM-003/006/009).

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// NormHandler exposes the normalization-quality endpoints.
type NormHandler struct{ q *NormQuality }

// NewNormHandler builds the handler.
func NewNormHandler(q *NormQuality) *NormHandler { return &NormHandler{q: q} }

// Quality handles GET /normalization/quality — per-source normalization health + drift flags.
func (h *NormHandler) Quality(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	rows, err := h.q.Quality(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"sources": rows})
}

// GetSettings handles GET /normalization/settings.
func (h *NormHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	set, err := h.q.GetSettings(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not load normalization settings"))
		return
	}
	httpx.JSON(w, http.StatusOK, set)
}

// SetSettings handles PUT /normalization/settings.
func (h *NormHandler) SetSettings(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in NormSettings
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	set, err := h.q.SetSettings(r.Context(), p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, set)
}
