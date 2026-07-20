package reporting

// §6.13 #125 R-4 — the report HTTP surface. Create/Get/Download. Download is an authenticated, role-gated GET (the
// route chain enforces the session); the service reads under WithTenant so RLS confines the artifact to the caller's
// tenant. The response is hardened: Content-Type pinned to the real format + nosniff, and a CRLF-safe RFC 6266
// Content-Disposition (refinement #4).

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// ReportHandler serves the report endpoints.
type ReportHandler struct{ svc *ReportService }

// NewReportHandler builds the handler.
func NewReportHandler(svc *ReportService) *ReportHandler { return &ReportHandler{svc: svc} }

type generateReq struct {
	Type   string `json:"type"`
	Format string `json:"format"`
}

// Create handles POST /reports — generate a report for the caller's tenant.
func (h *ReportHandler) Create(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in generateReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	rep, err := h.svc.Generate(r.Context(), p, in.Type, Format(in.Format))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, rep)
}

type breachReq struct {
	Incident string `json:"incident"`
	Format   string `json:"format"`
}

// Breach handles POST /reports/breach — generate a regulatory breach-notification report for one incident in the
// caller's tenant. The incident id comes from the JSON body; the service reads it under WithTenant so RLS confines
// the lookup (a foreign-tenant id resolves to not-found).
func (h *ReportHandler) Breach(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in breachReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	incidentID, err := uuid.Parse(in.Incident)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	rep, err := h.svc.GenerateBreachReport(r.Context(), p, incidentID, Format(in.Format))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, rep)
}

func reportID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return uuid.Nil, httpx.ErrBadRequest("invalid report id")
	}
	return id, nil
}

// Get handles GET /reports/{id} — the report record/status.
func (h *ReportHandler) Get(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := reportID(r)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	rep, err := h.svc.Get(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, rep)
}

// PendingApproval handles GET /reports/pending-approval — the senior-gated queue of reports awaiting sign-off.
func (h *ReportHandler) PendingApproval(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	reps, err := h.svc.ListPendingApproval(r.Context(), p)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"reports": reps})
}

// Approve handles POST /reports/{id}/approve — a senior actor (≠ creator) clears a review-required report.
func (h *ReportHandler) Approve(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := reportID(r)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	rep, err := h.svc.Approve(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, rep)
}

type rejectReq struct {
	Reason string `json:"reason"`
}

// Reject handles POST /reports/{id}/reject — a senior actor (≠ creator) blocks a report from release (terminal).
func (h *ReportHandler) Reject(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := reportID(r)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	var in rejectReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	rep, err := h.svc.Reject(r.Context(), p, id, in.Reason)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, rep)
}

// Download handles GET /reports/{id}/download — session-authorized artifact download with a hardened response.
func (h *ReportHandler) Download(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := reportID(r)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	data, format, err := h.svc.Download(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	fname := safeFilename("report-" + id.String() + format.Ext())
	w.Header().Set("Content-Type", format.ContentType())                      // pinned to the real format
	w.Header().Set("X-Content-Type-Options", "nosniff")                       // no MIME sniffing
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`) // CRLF-safe, RFC 6266
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
