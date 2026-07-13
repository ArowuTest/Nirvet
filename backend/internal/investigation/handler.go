package investigation

// §6.9 #124 I-1 — the investigation HTTP surface. Thin: decode → service → JSON. The routes are provider-gated
// (analyst_t1+) in the router; the allow-list/role/cost/audit controls live in the service.

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes the investigation query + entity + timeline + data-gap endpoints.
type Handler struct {
	svc      *Service
	entities *EntityService
	datagaps *DataGapService
}

// NewHandler builds the handler.
func NewHandler(svc *Service, entities *EntityService, datagaps *DataGapService) *Handler {
	return &Handler{svc: svc, entities: entities, datagaps: datagaps}
}

// defaultTimelineWindow is applied when a get-timeline request omits from/to.
const defaultTimelineWindow = 7 * 24 * time.Hour

// GetRawEvent handles GET /investigation/raw-event/{id} — fetch the untransformed raw payload for one raw event.
// The most sensitive read: role-gated at the router (senior+), RLS-confined, and fail-closed-audited in the service.
// The payload is returned base64-encoded so it is format-agnostic and safe to embed in JSON.
func (h *Handler) GetRawEvent(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid raw event id"))
		return
	}
	raw, err := h.svc.GetRawEvent(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"id":             raw.ID,
		"checksum":       raw.Checksum,
		"payload_base64": base64.StdEncoding.EncodeToString(raw.Payload),
	})
}

// RunHunt handles POST /investigation/run-hunt-query and PATCH /investigation/search-events (same allow-listed engine).
func (h *Handler) RunHunt(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var q HuntQuery
	if err := httpx.Decode(r, &q); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.RunHunt(r.Context(), p, q)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// EntityProfile handles GET /investigation/get-entity-profile?ref=kind:value (API-INV-002).
func (h *Handler) EntityProfile(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	res, err := h.entities.GetProfile(r.Context(), p, r.URL.Query().Get("ref"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// EntityGraph handles GET /investigation/get-entity-graph?ref=kind:value (API-INV-003) — the typed pivot.
func (h *Handler) EntityGraph(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	res, err := h.entities.Pivot(r.Context(), p, r.URL.Query().Get("ref"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// GetTimeline handles GET /investigation/get-timeline?ref=&from=&to= (API-INV-004). from/to are RFC3339; when omitted
// they default to the last defaultTimelineWindow so the mandatory bounded window is always satisfied.
func (h *Handler) GetTimeline(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	to := time.Now()
	from := to.Add(-defaultTimelineWindow)
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		}
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		}
	}
	res, err := h.svc.GetTimeline(r.Context(), p, r.URL.Query().Get("ref"), from, to)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// CaseTimeline handles GET /investigation/case-timeline?incident=&refs=&from=&to= (#188). refs is an optional
// comma-separated list of entity refs for the forensic event lane; from/to are RFC3339 (default: last window).
func (h *Handler) CaseTimeline(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	incID, err := uuid.Parse(r.URL.Query().Get("incident"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid or missing incident id"))
		return
	}
	to := time.Now()
	from := to.Add(-defaultTimelineWindow)
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		}
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		}
	}
	var refs []string
	if v := strings.TrimSpace(r.URL.Query().Get("refs")); v != "" {
		refs = strings.Split(v, ",")
	}
	res, err := h.svc.GetCaseTimeline(r.Context(), p, incID, refs, from, to)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// DataGaps handles GET /investigation/data-gaps (INV-009) — the unified "what you are not seeing" panel.
func (h *Handler) DataGaps(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	httpx.JSON(w, http.StatusOK, h.datagaps.Get(r.Context(), p))
}
