package threatintel

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// maxBundleBytes caps a STIX bundle upload so a hostile/huge payload can't exhaust memory.
const maxBundleBytes = 8 << 20 // 8 MiB

// Handler exposes watchlist endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Add handles POST /threat-intel.
func (h *Handler) Add(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in AddInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	ind, err := h.svc.Add(r.Context(), p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, ind)
}

// List handles GET /threat-intel.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	inds, err := h.svc.List(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list indicators"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"indicators": inds})
}

// AddStix handles POST /threat-intel/stix — analyst submission of a single STIX object.
func (h *Handler) AddStix(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in StixInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	o, err := h.svc.AddStix(r.Context(), p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, o)
}

// ImportBundle handles POST /threat-intel/stix/bundle — import a STIX 2.1 bundle.
func (h *Handler) ImportBundle(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBundleBytes))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("could not read bundle"))
		return
	}
	res, err := h.svc.ImportBundle(r.Context(), p.TenantID, json.RawMessage(body))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// ListStix handles GET /threat-intel/stix (optional ?type= and ?limit=).
func (h *Handler) ListStix(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	objs, err := h.svc.ListStix(r.Context(), p.TenantID, r.URL.Query().Get("type"), limit)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list STIX objects"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"objects": objs})
}

// GetStix handles GET /threat-intel/stix/{id}.
func (h *Handler) GetStix(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	o, err := h.svc.GetStix(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not load STIX object"))
		return
	}
	if o == nil {
		httpx.Error(w, httpx.ErrNotFound("STIX object not found"))
		return
	}
	httpx.JSON(w, http.StatusOK, o)
}
