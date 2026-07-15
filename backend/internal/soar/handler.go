package soar

import (
	"errors"
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes SOAR endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// SetAuthority handles POST /soar/authority with {"mode":"observe|approval|pre_authorised|emergency"}.
func (h *Handler) SetAuthority(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		Mode string `json:"mode"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.SetAuthority(r.Context(), p, p.TenantID, AuthorityMode(in.Mode)); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"authority_mode": in.Mode})
}

// ListActionCatalog handles GET /soar/action-catalog (effective catalog: global + tenant overrides).
func (h *Handler) ListActionCatalog(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	cs, err := h.svc.ListActionCatalog(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"actions": cs})
}

// SetActionCatalog handles PUT /soar/action-catalog (upsert a tenant override for an action).
func (h *Handler) SetActionCatalog(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in ActionCatalogInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	a, err := h.svc.SetActionCatalog(r.Context(), p, p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, a)
}

// Reverse handles POST /soar/runs/{id}/reverse — undo a run's real containment (MUST-3).
func (h *Handler) Reverse(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid run id"))
		return
	}
	res, err := h.svc.Reverse(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"reversed": res})
}

// GetSettings handles GET /soar/settings (per-tenant destructive-action config).
func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	set, err := h.svc.Settings(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, set)
}

// SetSettings handles PUT /soar/settings (platform-admin: enable/tune destructive actions for a tenant).
func (h *Handler) SetSettings(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in SoarSettings
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	set, err := h.svc.SetSettings(r.Context(), p, p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, set)
}

// GetPlatform handles GET /soar/platform (global kill-switch + dry-run).
func (h *Handler) GetPlatform(w http.ResponseWriter, r *http.Request) {
	f, err := h.svc.PlatformFlags(r.Context())
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, f)
}

// SetPlatform handles PUT /soar/platform (platform-admin: the global kill-switch / dry-run emergency stop).
func (h *Handler) SetPlatform(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in PlatformFlags
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	f, err := h.svc.SetPlatformFlags(r.Context(), p, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, f)
}

// ListPlaybooks handles GET /playbooks.
func (h *Handler) ListPlaybooks(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	pbs, err := h.svc.ListPlaybooks(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list playbooks"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"playbooks": pbs})
}

// Run handles POST /playbooks/{id}/run with optional {"incident_id": "..."}.
func (h *Handler) Run(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid playbook id"))
		return
	}
	var in struct {
		IncidentID string `json:"incident_id"`
	}
	_ = httpx.Decode(r, &in)
	var incidentID *uuid.UUID
	if in.IncidentID != "" {
		if iid, err := uuid.Parse(in.IncidentID); err == nil {
			incidentID = &iid
		}
	}
	run, err := h.svc.Run(r.Context(), p, id, incidentID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, run)
}

// ListRuns handles GET /soar/runs.
func (h *Handler) ListRuns(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	runs, err := h.svc.ListRuns(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list runs"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"runs": runs})
}

// GetRun handles GET /soar/runs/{id}.
func (h *Handler) GetRun(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid run id"))
		return
	}
	run, err := h.svc.GetRun(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}

// Approve handles POST /soar/runs/{id}/approve.
func (h *Handler) Approve(w http.ResponseWriter, r *http.Request) { h.decision(w, r, true) }

// Reject handles POST /soar/runs/{id}/reject.
func (h *Handler) Reject(w http.ResponseWriter, r *http.Request) { h.decision(w, r, false) }

func (h *Handler) decision(w http.ResponseWriter, r *http.Request, approve bool) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid run id"))
		return
	}
	var run *PlaybookRun
	if approve {
		run, err = h.svc.Approve(r.Context(), p, id)
	} else {
		run, err = h.svc.Reject(r.Context(), p, id)
	}
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}

// IssueApprovalLink handles POST /soar/runs/{id}/approval-link — mint a single-use, run-bound customer approval
// link for a pending run (#188). Gated to the same seniority as approval (soarApprover). Returns the raw token once.
func (h *Handler) IssueApprovalLink(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid run id"))
		return
	}
	token, err := h.svc.IssueApprovalLink(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]string{"token": token})
}

// ApproveViaLink handles POST /soar/approve-link — the PUBLIC customer approval path (#188). No session: the
// single-use token in the body is the capability (it resolves the tenant + run and is consumed atomically).
func (h *Handler) ApproveViaLink(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	run, err := h.svc.ApproveViaLink(r.Context(), in.Token)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}

// customerSafeError enforces the AUDIENCE BOUNDARY on SOAR refusals (J3).
//
// The approval gate refuses in prose that names internal SOC state: whether the internal approver is still
// employed ("the internal approver is no longer active"), the internal role taxonomy and a named analyst's tier
// ("approver role 'analyst_t2' is insufficient to approve a high-risk action"), requester attribution and
// four-eyes mechanics. Those are exactly the facts the read-model withholds from a customer audience — and prose
// crosses that boundary as easily as a count did in BUG-10. Fixing this in the portal UI would not do: the text
// still ships in the HTTP body, one devtools panel away.
//
// Positive allowlist, fail-closed — the same shape as the read-model projection: refusals ABOUT THE CUSTOMER'S OWN
// request or their own tenant policy pass through; everything else collapses to a generic notice. A refusal we
// have not explicitly classified as customer-safe is treated as internal.
func customerSafeError(err error) error {
	var ae *httpx.APIError
	if !errors.As(err, &ae) {
		return httpx.ErrInternal("could not record your decision")
	}
	switch ae.Code {
	case "bad_request", "not_found", "conflict":
		return ae // about the caller's own request (bad id, stale run) — safe and actionable
	}
	if ae.Status == http.StatusForbidden && ae.Message == MsgCustomerApprovalDisabled {
		return ae // about the customer's OWN tenant policy — safe and actionable
	}
	// Everything else at this boundary is internal gate state. Say only what the customer can act on; the real
	// reason stays server-side (the run's approval trail already records it for the SOC).
	return httpx.ErrForbidden("this action can no longer be authorised from the portal — please contact your SOC")
}

// CustomerApprove handles POST /customer/soar/approvals/{id}/approve — the IN-PORTAL authenticated customer
// approval (SB3). customer_admin only (gated at the route); RLS-scoped to their own tenant. Refusals pass through
// customerSafeError so the gate's internal reasoning never reaches the customer (J3).
func (h *Handler) CustomerApprove(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid run id"))
		return
	}
	run, err := h.svc.ApproveAsCustomer(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, customerSafeError(err))
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}

// CustomerReject handles POST /customer/soar/approvals/{id}/reject — the in-portal customer rejection (fail-safe).
func (h *Handler) CustomerReject(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid run id"))
		return
	}
	run, err := h.svc.RejectAsCustomer(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, customerSafeError(err)) // J3: same audience boundary as approve
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}

// GetCustomerApprovalPolicy handles GET /soar/customer-approval — the tenant's destructive-approval authority (#188).
func (h *Handler) GetCustomerApprovalPolicy(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	httpx.JSON(w, http.StatusOK, h.svc.GetCustomerPolicy(r.Context(), p))
}

// SetCustomerApprovalPolicy handles PUT /soar/customer-approval — set the authority routing (#188).
func (h *Handler) SetCustomerApprovalPolicy(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in CustomerApprovalPolicy
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.SetCustomerPolicy(r.Context(), p, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// ListActionRecords handles GET /soar/action-records — the durable records internal executors wrote (#187 slice C).
func (h *Handler) ListActionRecords(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	recs, err := h.svc.ListActionRecords(r.Context(), p.TenantID, 100)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"records": recs})
}

// CreatePlaybook handles POST /soar/playbooks — author a tenant-owned playbook (#187 slice A, soc_manager+).
func (h *Handler) CreatePlaybook(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in PlaybookInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	pb, err := h.svc.CreatePlaybook(r.Context(), p, p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, pb)
}

// UpdatePlaybook handles PUT /soar/playbooks/{id} — replace a tenant playbook's body (soc_manager+).
func (h *Handler) UpdatePlaybook(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid playbook id"))
		return
	}
	var in PlaybookInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	pb, err := h.svc.UpdatePlaybook(r.Context(), p, p.TenantID, id, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, pb)
}

// SetPlaybookEnabled handles PATCH /soar/playbooks/{id}/enabled with {"enabled":bool} (soc_manager+).
func (h *Handler) SetPlaybookEnabled(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid playbook id"))
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.SetPlaybookEnabled(r.Context(), p, p.TenantID, id, in.Enabled); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"id": id, "enabled": in.Enabled})
}
