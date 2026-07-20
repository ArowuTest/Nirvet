package asset

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes asset-inventory endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Create handles POST /assets (register or update an asset).
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in CreateInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	a, err := h.svc.Create(r.Context(), p, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, a)
}

// BulkCreate handles POST /assets/bulk with {"items":[...]} — import many assets at once (#188).
func (h *Handler) BulkCreate(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		Items []CreateInput `json:"items"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.BulkCreate(r.Context(), p, in.Items)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// List handles GET /assets.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	assets, err := h.svc.List(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list assets"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"assets": assets})
}

// Posture handles GET /assets/posture — the attack-surface/exposure summary (inventory breakdowns + live vulns).
func (h *Handler) Posture(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	pos, err := h.svc.Posture(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not compute asset posture"))
		return
	}
	httpx.JSON(w, http.StatusOK, pos)
}

// Identities handles GET /assets/identities — the identity (user-kind) inventory with per-asset confidence.
func (h *Handler) Identities(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	ids, err := h.svc.Identities(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list identities"))
		return
	}
	if ids == nil {
		ids = []IdentityAsset{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"identities": ids})
}

// Get handles GET /assets/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid asset id"))
		return
	}
	a, err := h.svc.Get(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, a)
}
