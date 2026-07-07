package ingestion

import (
	"net/http"
	"strconv"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Handler exposes ingest + event-query endpoints.
type Handler struct {
	svc    *Service
	events eventstore.EventStore
}

// NewHandler builds the handler.
func NewHandler(svc *Service, events eventstore.EventStore) *Handler {
	return &Handler{svc: svc, events: events}
}

// Ingest handles POST /ingest. Authenticated; uses the principal's tenant.
// (Production: per-tenant source API keys / connector identity.)
func (h *Handler) Ingest(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in IngestInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	dedupe, err := h.svc.Ingest(r.Context(), p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, map[string]string{"status": "accepted", "dedupe_key": dedupe})
}

// Events handles GET /events?severity=&search=&limit=.
func (h *Handler) Events(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	q := eventstore.Query{
		Severity: r.URL.Query().Get("severity"),
		Search:   r.URL.Query().Get("search"),
		Limit:    limit,
	}
	evs, err := h.events.Query(r.Context(), p.TenantID, q)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not query events"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"events": evs})
}
