package audit

// HTTP surface for the immutable audit trail (SRS §11.2 GOV-001; ADMIN-004). Read-only, tenant-scoped by RLS
// (FindByActionContains reads under WithTenant), and gated at the route to platform_admin ONLY (padmin) — the raw
// audit_log is an operator/governance surface that mixes operator (MSSP) actions with tenant actions, so it must
// NOT be exposed to customer_admin; a customer's own activity view goes through the audience-fenced read-model. A
// caller can search by a substring of the action or target and cap the result; entries are most-recent-first.

import (
	"net/http"
	"strconv"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Handler serves the audit-log read endpoint.
type Handler struct{ db *database.DB }

// NewHandler builds the handler.
func NewHandler(db *database.DB) *Handler { return &Handler{db: db} }

// List handles GET /admin/audit?q=&limit= — search the caller's tenant audit trail (most-recent-first).
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	q := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := FindByActionContains(r.Context(), h.db, p.TenantID, q, limit)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not read audit log"))
		return
	}
	// FindByActionContains returns oldest-first; reverse to most-recent-first for the console.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"entries": entries})
}
