package incident

import (
	"io"
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// maxAttachmentBytes caps an evidence upload (CASE-008).
const maxAttachmentBytes = 25 << 20 // 25 MiB

// Handler exposes incident endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// PromoteFromAlert handles POST /alerts/{id}/promote.
func (h *Handler) PromoteFromAlert(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid alert id"))
		return
	}
	inc, err := h.svc.CreateFromAlert(r.Context(), p, alertID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, inc)
}

// Create handles POST /incidents — an analyst-declared incident (CASE-001), not promoted from an alert.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in ManualInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	inc, err := h.svc.CreateManual(r.Context(), p, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, inc)
}

// AtRisk handles GET /incidents/at-risk — open incidents breaching/near-breaching SLA.
func (h *Handler) AtRisk(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	xs, err := h.svc.AtRisk(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"incidents": xs})
}

// List handles GET /incidents.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	xs, err := h.svc.List(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"incidents": xs})
}

// Get handles GET /incidents/{id} (includes timeline).
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	inc, err := h.svc.Get(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	tl, _ := h.svc.Timeline(r.Context(), p.TenantID, id)
	httpx.JSON(w, http.StatusOK, map[string]any{"incident": inc, "timeline": tl})
}

// Assign handles POST /incidents/{id}/assign — hand the case to an analyst.
func (h *Handler) Assign(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	var in struct {
		AssigneeID string `json:"assignee_id"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	assignee, err := uuid.Parse(in.AssigneeID)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid assignee_id"))
		return
	}
	if err := h.svc.Assign(r.Context(), p, id, assignee); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "assigned"})
}

// AddNote handles POST /incidents/{id}/notes with optional {"visibility":"internal|customer"}.
func (h *Handler) AddNote(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	var in struct {
		Note       string `json:"note"`
		Visibility string `json:"visibility"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.AddNote(r.Context(), p, id, in.Note, in.Visibility); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]string{"status": "note_added"})
}

// CustomerTimeline handles GET /incidents/{id}/customer-timeline — customer-visible entries only.
func (h *Handler) CustomerTimeline(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	tl, err := h.svc.CustomerTimeline(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"timeline": tl})
}

// Transition handles POST /incidents/{id}/transition with {"stage":"...","note":"..."} (CASE-002).
func (h *Handler) Transition(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	var in struct {
		Stage string `json:"stage"`
		Note  string `json:"note"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	inc, err := h.svc.Transition(r.Context(), p, id, Stage(in.Stage), in.Note)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, inc)
}

// Close handles POST /incidents/{id}/close with the CASE-009 closure criteria.
func (h *Handler) Close(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	var in ClosureInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	inc, err := h.svc.Close(r.Context(), p, id, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, inc)
}

// pathID parses the {id} path value or writes a 400 and returns ok=false.
func pathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return uuid.Nil, false
	}
	return id, true
}

// CreateTask handles POST /incidents/{id}/tasks (CASE-005).
func (h *Handler) CreateTask(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in TaskInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	t, err := h.svc.CreateTask(r.Context(), p, id, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, t)
}

// ListTasks handles GET /incidents/{id}/tasks.
func (h *Handler) ListTasks(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	tasks, err := h.svc.ListTasks(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list tasks"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"tasks": tasks})
}

// UpdateTask handles PUT /incidents/tasks/{id} with {"status":"..."}.
func (h *Handler) UpdateTask(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Status string `json:"status"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.UpdateTaskStatus(r.Context(), p, id, in.Status); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": in.Status})
}

// ListCategories handles GET /incident-categories (CASE-007).
func (h *Handler) ListCategories(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	cats, err := h.svc.ListCategories(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list categories"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"categories": cats})
}

// SetCategory handles PUT /incidents/{id}/category with {"category":"..."}.
func (h *Handler) SetCategory(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Category string `json:"category"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.SetCategory(r.Context(), p, id, in.Category); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"category": in.Category})
}

// LinkParent handles POST /incidents/{id}/parent with {"parent_id":"..."} (CASE-006). An empty/absent
// parent_id unlinks.
func (h *Handler) LinkParent(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		ParentID string `json:"parent_id"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if in.ParentID == "" {
		if err := h.svc.UnlinkParent(r.Context(), p, id); err != nil {
			httpx.Error(w, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "unlinked"})
		return
	}
	parentID, err := uuid.Parse(in.ParentID)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid parent_id"))
		return
	}
	if err := h.svc.LinkParent(r.Context(), p, id, parentID); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "linked"})
}

// SetMajor handles PUT /incidents/{id}/major with {"is_major":true|false}.
func (h *Handler) SetMajor(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		IsMajor bool `json:"is_major"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.SetMajor(r.Context(), p, id, in.IsMajor); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]bool{"is_major": in.IsMajor})
}

// Children handles GET /incidents/{id}/children.
func (h *Handler) Children(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	kids, err := h.svc.Children(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list children"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"children": kids})
}

// AddAttachment handles POST /incidents/{id}/attachments — raw body is the evidence file; filename and
// content-type come from query/header (CASE-008 chain-of-custody).
func (h *Handler) AddAttachment(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxAttachmentBytes))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("could not read attachment"))
		return
	}
	filename := r.URL.Query().Get("filename")
	contentType := r.Header.Get("Content-Type")
	a, err := h.svc.RegisterAttachment(r.Context(), p, id, filename, contentType, data, r.URL.Query().Get("note"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, a)
}

// ListAttachments handles GET /incidents/{id}/attachments.
func (h *Handler) ListAttachments(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	xs, err := h.svc.ListAttachments(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list attachments"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"attachments": xs})
}

// ListKB handles GET /knowledge-base — global + tenant articles.
func (h *Handler) ListKB(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	xs, err := h.svc.ListArticles(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list knowledge base"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"articles": xs})
}

// CreateKB handles POST /knowledge-base.
func (h *Handler) CreateKB(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in ArticleInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	a, err := h.svc.CreateArticle(r.Context(), p, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, a)
}

// LinkKB handles POST /incidents/{id}/kb-links with {"article_id":"..."}.
func (h *Handler) LinkKB(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		ArticleID string `json:"article_id"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	articleID, err := uuid.Parse(in.ArticleID)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid article_id"))
		return
	}
	if err := h.svc.LinkArticle(r.Context(), p, id, articleID); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "linked"})
}

// ListKBLinks handles GET /incidents/{id}/kb-links.
func (h *Handler) ListKBLinks(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	xs, err := h.svc.LinkedArticles(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list linked articles"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"articles": xs})
}
