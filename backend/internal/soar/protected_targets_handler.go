package soar

// HTTP surface for the D5 protected-target deny-lists. Gated asymmetrically in cmd/api/main.go:
// GET = provider (any internal responder may see why a run was withheld), POST = manager (tightens),
// DELETE = padmin (weakens).

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// ListProtectedTargets handles GET /soar/protected-targets/{kind}.
func (h *Handler) ListProtectedTargets(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	kind, err := ParseProtectedKind(r.PathValue("kind"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	list, err := h.svc.ProtectedTargets(r.Context(), p.TenantID, kind)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, list)
}

// AddProtectedTarget handles POST /soar/protected-targets/{kind} (soc-manager: tighten the blast-radius net).
func (h *Handler) AddProtectedTarget(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	kind, err := ParseProtectedKind(r.PathValue("kind"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	var in struct {
		Value string `json:"value"`
		Note  string `json:"note"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	t, err := h.svc.AddProtectedTarget(r.Context(), p, kind, in.Value, in.Note)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, t)
}

// RemoveProtectedTarget handles DELETE /soar/protected-targets/{kind}/{id} (platform-admin: this WEAKENS the net,
// so it sits a tier above the add).
func (h *Handler) RemoveProtectedTarget(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	kind, err := ParseProtectedKind(r.PathValue("kind"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid id"))
		return
	}
	if err := h.svc.RemoveProtectedTarget(r.Context(), p, kind, id); err != nil {
		httpx.Error(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
