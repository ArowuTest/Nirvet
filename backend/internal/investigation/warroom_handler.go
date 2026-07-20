package investigation

// HTTP surface for the war-room (§6.9). All routes are provider-gated at the mux; the real access control is the
// membership RLS + the per-read incident-access check + owner-only mutations in the service.

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// WarRoomHandler serves the war-room endpoints.
type WarRoomHandler struct{ svc *WarRoomService }

// NewWarRoomHandler builds the handler.
func NewWarRoomHandler(svc *WarRoomService) *WarRoomHandler { return &WarRoomHandler{svc: svc} }

func (h *WarRoomHandler) roomID(r *http.Request) (uuid.UUID, error) {
	return uuid.Parse(r.PathValue("id"))
}

// Create handles POST /investigation/war-rooms.
func (h *WarRoomHandler) Create(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		IncidentRef string `json:"incident_ref"`
		Title       string `json:"title"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	incidentRef, err := uuid.Parse(in.IncidentRef)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident_ref"))
		return
	}
	room, err := h.svc.CreateRoom(r.Context(), p, incidentRef, in.Title)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, room)
}

// List handles GET /investigation/war-rooms.
func (h *WarRoomHandler) List(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	rooms, err := h.svc.ListRooms(r.Context(), p)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"war_rooms": rooms})
}

// Get handles GET /investigation/war-rooms/{id}.
func (h *WarRoomHandler) Get(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := h.roomID(r)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid room id"))
		return
	}
	room, err := h.svc.GetRoom(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, room)
}

// Invite handles POST /investigation/war-rooms/{id}/members.
func (h *WarRoomHandler) Invite(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := h.roomID(r)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid room id"))
		return
	}
	var in struct {
		UserID string `json:"user_id"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	invitee, err := uuid.Parse(in.UserID)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid user_id"))
		return
	}
	if err := h.svc.Invite(r.Context(), p, id, invitee); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// RemoveMember handles DELETE /investigation/war-rooms/{id}/members/{uid}.
func (h *WarRoomHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := h.roomID(r)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid room id"))
		return
	}
	member, err := uuid.Parse(r.PathValue("uid"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid member id"))
		return
	}
	if err := h.svc.RemoveMember(r.Context(), p, id, member); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Archive handles POST /investigation/war-rooms/{id}/archive.
func (h *WarRoomHandler) Archive(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := h.roomID(r)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid room id"))
		return
	}
	if err := h.svc.Archive(r.Context(), p, id); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ListEntries handles GET /investigation/war-rooms/{id}/entries.
func (h *WarRoomHandler) ListEntries(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := h.roomID(r)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid room id"))
		return
	}
	entries, err := h.svc.ListEntries(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// AddEntry handles POST /investigation/war-rooms/{id}/entries.
func (h *WarRoomHandler) AddEntry(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := h.roomID(r)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid room id"))
		return
	}
	var in EntryInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	e, err := h.svc.AddEntry(r.Context(), p, id, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, e)
}

// RunEntry handles POST /investigation/war-rooms/{id}/entries/{eid}/run.
func (h *WarRoomHandler) RunEntry(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := h.roomID(r)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid room id"))
		return
	}
	entryID, err := uuid.Parse(r.PathValue("eid"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid entry id"))
		return
	}
	res, err := h.svc.RunEntryQuery(r.Context(), p, id, entryID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}
