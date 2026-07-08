package iam

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes IAM endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Login handles POST /auth/login (public).
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		MFACode  string `json:"mfa_code"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.Login(r.Context(), in.Email, in.Password, in.MFACode, httpx.RequestIDFrom(r.Context()))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// Create handles POST /admin/users. A platform_admin may target any tenant via
// tenant_id; otherwise the user is created in the caller's tenant.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		CreateInput
		TenantID string `json:"tenant_id"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	tenantID := p.TenantID
	if p.Role == auth.RolePlatformAdmin && in.TenantID != "" {
		id, err := uuid.Parse(in.TenantID)
		if err != nil {
			httpx.Error(w, httpx.ErrBadRequest("invalid tenant_id"))
			return
		}
		tenantID = id
	}
	u, err := h.svc.Create(r.Context(), tenantID, in.CreateInput)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, u)
}

// EnrollMFA handles POST /mfa/enroll — returns the otpauth URI + secret (once).
func (h *Handler) EnrollMFA(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	uri, secret, err := h.svc.EnrollMFA(r.Context(), p)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"otpauth_uri": uri, "secret": secret})
}

// ActivateMFA handles POST /mfa/activate with {"code":"123456"}.
func (h *Handler) ActivateMFA(w http.ResponseWriter, r *http.Request) { h.mfaAction(w, r, true) }

// DisableMFA handles POST /mfa/disable with {"code":"123456"}.
func (h *Handler) DisableMFA(w http.ResponseWriter, r *http.Request) { h.mfaAction(w, r, false) }

func (h *Handler) mfaAction(w http.ResponseWriter, r *http.Request, activate bool) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		Code string `json:"code"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	var err error
	if activate {
		err = h.svc.ActivateMFA(r.Context(), p, in.Code)
	} else {
		err = h.svc.DisableMFA(r.Context(), p, in.Code)
	}
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]bool{"mfa_enabled": activate})
}

// ChangePassword handles POST /me/password with
// {"current_password":"...","new_password":"..."}.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		httpx.Error(w, httpx.ErrUnauthorized("not authenticated"))
		return
	}
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.ChangePassword(r.Context(), p, in.CurrentPassword, in.NewPassword); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]bool{"changed": true})
}

// Me handles GET /me.
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		httpx.Error(w, httpx.ErrUnauthorized("not authenticated"))
		return
	}
	u, err := h.svc.Me(r.Context(), p)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, u)
}
