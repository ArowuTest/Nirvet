package connector

import (
	"net/http"
	"time"

	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes connector management + the public webhook ingest endpoint.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Catalogue handles GET /connectors/catalogue (available connector types).
func (h *Handler) Catalogue(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{"catalogue": Registry()})
}

// SetCredExpiry handles PUT /connectors/{id}/cred-expiry with {"expires_at": "<RFC3339>"|null} (#188). Records the
// connector credential's expiry so the platform can remind the tenant before it lapses; null clears it.
func (h *Handler) SetCredExpiry(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid connector id"))
		return
	}
	var in struct {
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.SetCredExpiry(r.Context(), p.TenantID, id, in.ExpiresAt); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"id": id, "cred_expires_at": in.ExpiresAt})
}

// Create handles POST /connectors.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in CreateInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.Create(r.Context(), p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, res)
}

// List handles GET /connectors.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	cs, err := h.svc.List(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list connectors"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"connectors": cs})
}

// Delete handles DELETE /connectors/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid connector id"))
		return
	}
	if err := h.svc.Delete(r.Context(), p.TenantID, id); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// TestConnection handles POST /connectors/{id}/test — a live credential + connectivity probe (tenant-scoped).
// Always 200 with a {status, detail} body: status=ok|failed|not_applicable. A "failed" connection is a valid
// probe outcome, not an HTTP error.
func (h *Handler) TestConnection(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid connector id"))
		return
	}
	res, err := h.svc.TestConnection(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// Webhook handles POST /ingest/webhook/{id} — PUBLIC, authenticated by the
// X-Nirvet-Key header against the connector's stored key hash.
func (h *Handler) Webhook(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid connector id"))
		return
	}
	key := r.Header.Get("X-Nirvet-Key")
	if key == "" {
		httpx.Error(w, httpx.ErrUnauthorized("missing X-Nirvet-Key"))
		return
	}
	var body struct {
		Events []ingestion.IngestInput `json:"events"`
	}
	if err := httpx.Decode(r, &body); err != nil {
		httpx.Error(w, err)
		return
	}
	accepted, err := h.svc.IngestWebhook(r.Context(), id, key, body.Events)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, map[string]int{"accepted": accepted})
}
