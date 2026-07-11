package platformadmin

// §6.18 #122 P-5 — the platform-admin HTTP surface. All routes are padmin-gated in the router; the security gates
// (safety class, four-eyes, legal-hold, maintenance) live in the services. Thin plumbing: decode → service → JSON.

import (
	"net/http"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes the platform-admin config/lifecycle/maintenance endpoints.
type Handler struct {
	svc   *Service
	maint *MaintenanceService
}

// NewHandler builds the handler.
func NewHandler(svc *Service, maint *MaintenanceService) *Handler {
	return &Handler{svc: svc, maint: maint}
}

// SetFlag handles PUT /admin/flags.
func (h *Handler) SetFlag(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in SetFlagInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.SetFlag(r.Context(), p, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

type rollbackReq struct {
	AuditID    uuid.UUID  `json:"audit_id"`
	ApprovedBy *uuid.UUID `json:"approved_by"`
}

// RollbackFlag handles POST /admin/flags/rollback.
func (h *Handler) RollbackFlag(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in rollbackReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.RollbackFlag(r.Context(), p, in.AuditID, in.ApprovedBy)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

type reasonReq struct {
	Reason     string     `json:"reason"`
	ApprovedBy *uuid.UUID `json:"approved_by"`
}

func tenantIDFrom(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return uuid.Nil, httpx.ErrBadRequest("invalid tenant id")
	}
	return id, nil
}

// SetLegalHold handles POST /admin/tenants/{id}/legal-hold.
func (h *Handler) SetLegalHold(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	tid, err := tenantIDFrom(r)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	var in reasonReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.SetLegalHold(r.Context(), p, tid, in.Reason); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "legal_hold_set"})
}

// ClearLegalHold handles DELETE /admin/tenants/{id}/legal-hold (M-3: elevated envelope).
func (h *Handler) ClearLegalHold(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	tid, err := tenantIDFrom(r)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	var in reasonReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.ClearLegalHold(r.Context(), p, tid, in.Reason, in.ApprovedBy); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "legal_hold_cleared"})
}

// MarkExported handles POST /admin/tenants/{id}/mark-exported — the required precondition of offboarding.
func (h *Handler) MarkExported(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	tid, err := tenantIDFrom(r)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	var in reasonReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.MarkExported(r.Context(), p, tid, in.Reason); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "exported"})
}

// OffboardTenant handles POST /admin/tenants/{id}/offboard — irreversible; requires the elevated envelope
// (senior + four-eyes via approved_by + reason), and the tenant must be exported with its retention window elapsed.
func (h *Handler) OffboardTenant(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	tid, err := tenantIDFrom(r)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	var in reasonReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	cert, err := h.svc.OffboardTenant(r.Context(), p, tid, in.Reason, in.ApprovedBy)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted", "certificate_of_destruction": cert})
}

type windowReq struct {
	Scope                 string    `json:"scope"`
	ScopeRef              string    `json:"scope_ref"`
	StartsAt              time.Time `json:"starts_at"`
	EndsAt                time.Time `json:"ends_at"`
	SuppressNotifications bool      `json:"suppress_notifications"`
	PauseSLA              bool      `json:"pause_sla"`
	Banner                string    `json:"banner"`
}

// CreateWindow handles POST /admin/maintenance-windows.
func (h *Handler) CreateWindow(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in windowReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.maint.CreateWindow(r.Context(), p, in.Scope, in.ScopeRef, in.StartsAt, in.EndsAt, in.SuppressNotifications, in.PauseSLA, in.Banner); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]string{"status": "created"})
}
