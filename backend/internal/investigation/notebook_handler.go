package investigation

// HTTP surface for investigation notebooks (B2). Provider-gated (analyst_t1+, the hunt tier). Notebooks are
// private to the caller (enforced in the repo via user_id).

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// CreateNotebook handles POST /investigation/notebooks.
func (h *Handler) CreateNotebook(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		Title       string  `json:"title"`
		IncidentRef *string `json:"incident_ref"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	var ref *uuid.UUID
	if in.IncidentRef != nil && *in.IncidentRef != "" {
		id, err := uuid.Parse(*in.IncidentRef)
		if err != nil {
			httpx.Error(w, httpx.ErrBadRequest("invalid incident_ref"))
			return
		}
		ref = &id
	}
	nb, err := h.svc.CreateNotebook(r.Context(), p, in.Title, ref)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, nb)
}

// ListNotebooks handles GET /investigation/notebooks.
func (h *Handler) ListNotebooks(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	nbs, err := h.svc.ListNotebooks(r.Context(), p)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"notebooks": nbs})
}

// GetNotebook handles GET /investigation/notebooks/{id}.
func (h *Handler) GetNotebook(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid notebook id"))
		return
	}
	nb, cells, err := h.svc.GetNotebook(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"notebook": nb, "cells": cells})
}

// AddCell handles POST /investigation/notebooks/{id}/cells.
func (h *Handler) AddCell(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid notebook id"))
		return
	}
	var in struct {
		Kind    string `json:"kind"`
		Content string `json:"content"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	c, err := h.svc.AddCell(r.Context(), p, id, in.Kind, in.Content)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, c)
}

// UpdateCell handles PUT /investigation/notebooks/{id}/cells/{cid}.
func (h *Handler) UpdateCell(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, cid, ok := notebookAndCell(w, r)
	if !ok {
		return
	}
	var in struct {
		Content string `json:"content"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.UpdateCell(r.Context(), p, id, cid, in.Content); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// DeleteCell handles DELETE /investigation/notebooks/{id}/cells/{cid}.
func (h *Handler) DeleteCell(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, cid, ok := notebookAndCell(w, r)
	if !ok {
		return
	}
	if err := h.svc.DeleteCell(r.Context(), p, id, cid); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// MoveCell handles POST /investigation/notebooks/{id}/cells/{cid}/move.
func (h *Handler) MoveCell(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, cid, ok := notebookAndCell(w, r)
	if !ok {
		return
	}
	var in struct {
		Dir string `json:"dir"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.MoveCell(r.Context(), p, id, cid, in.Dir); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "moved"})
}

func notebookAndCell(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid notebook id"))
		return uuid.Nil, uuid.Nil, false
	}
	cid, err := uuid.Parse(r.PathValue("cid"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid cell id"))
		return uuid.Nil, uuid.Nil, false
	}
	return id, cid, true
}
