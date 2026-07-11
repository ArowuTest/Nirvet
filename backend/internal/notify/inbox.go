package notify

// In-app notification feed (§6.16 launch-line, light). A per-user inbox: RLS enforces the TENANT boundary, and an
// explicit `recipient_id = caller` filter on EVERY read/write enforces the USER boundary — a user can only ever
// see or modify their own notifications, never another user's or another tenant's. Rows are written in-process by
// NotifyInApp (no new egress). A user may disable their own feed (notification_user_prefs).

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// InAppNotification is one row in a user's inbox (as returned to that user).
type InAppNotification struct {
	ID        uuid.UUID  `json:"id"`
	Kind      string     `json:"kind"`
	Subject   string     `json:"subject"`
	Body      string     `json:"body"`
	CreatedAt time.Time  `json:"created_at"`
	ReadAt    *time.Time `json:"read_at,omitempty"`
}

// Inbox is the per-user in-app notification feed.
type Inbox struct{ db *database.DB }

// NewInbox builds the inbox.
func NewInbox(db *database.DB) *Inbox { return &Inbox{db: db} }

const inboxMaxLimit = 200

// NotifyInApp inserts an in-app notification addressed to a specific user — unless that user has disabled their
// feed. This is the producer API: user-addressed events (assignment, approval-requested, a reset link, …) call it.
// Tenant-scoped; the recipient is a user id, never a free-form contact string.
func (in *Inbox) NotifyInApp(ctx context.Context, tenantID, recipientID uuid.UUID, kind, subject, body string) error {
	if subject == "" {
		return httpx.ErrBadRequest("subject is required")
	}
	if kind == "" {
		kind = "info"
	}
	return in.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Prefs: absent row = enabled (default true); only an explicit in_app_enabled=false suppresses delivery.
		enabled := true
		_ = tx.QueryRow(ctx, `SELECT in_app_enabled FROM notification_user_prefs WHERE user_id=$1`, recipientID).Scan(&enabled)
		if !enabled {
			return nil
		}
		_, e := tx.Exec(ctx,
			`INSERT INTO in_app_notifications (tenant_id, recipient_id, kind, subject, body) VALUES ($1,$2,$3,$4,$5)`,
			tenantID, recipientID, kind, subject, body)
		return e
	})
}

// List returns the CALLER'S OWN notifications, newest first (optionally only unread). recipient_id=userID is the
// user boundary; RLS is the tenant boundary.
func (in *Inbox) List(ctx context.Context, tenantID, userID uuid.UUID, onlyUnread bool, limit int) ([]InAppNotification, error) {
	if limit <= 0 || limit > inboxMaxLimit {
		limit = 50
	}
	out := []InAppNotification{}
	err := in.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		q := `SELECT id, kind, subject, body, created_at, read_at FROM in_app_notifications WHERE recipient_id=$1`
		if onlyUnread {
			q += ` AND read_at IS NULL`
		}
		q += ` ORDER BY created_at DESC LIMIT $2`
		rows, e := tx.Query(ctx, q, userID, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var n InAppNotification
			if e := rows.Scan(&n.ID, &n.Kind, &n.Subject, &n.Body, &n.CreatedAt, &n.ReadAt); e != nil {
				return e
			}
			out = append(out, n)
		}
		return rows.Err()
	})
	return out, err
}

// UnreadCount returns the caller's own unread count.
func (in *Inbox) UnreadCount(ctx context.Context, tenantID, userID uuid.UUID) (int, error) {
	var n int
	err := in.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM in_app_notifications WHERE recipient_id=$1 AND read_at IS NULL`, userID).Scan(&n)
	})
	return n, err
}

// MarkRead marks ONE of the caller's notifications read. The recipient_id guard means a caller can never mark
// another user's notification read, and (idempotent, non-revealing) a foreign/absent id simply affects 0 rows.
func (in *Inbox) MarkRead(ctx context.Context, tenantID, userID, id uuid.UUID) error {
	return in.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`UPDATE in_app_notifications SET read_at=now() WHERE id=$1 AND recipient_id=$2 AND read_at IS NULL`, id, userID)
		return e
	})
}

// MarkAllRead marks all of the caller's unread notifications read; returns how many were affected.
func (in *Inbox) MarkAllRead(ctx context.Context, tenantID, userID uuid.UUID) (int, error) {
	var n int
	err := in.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE in_app_notifications SET read_at=now() WHERE recipient_id=$1 AND read_at IS NULL`, userID)
		if e != nil {
			return e
		}
		n = int(ct.RowsAffected())
		return nil
	})
	return n, err
}

// GetPrefs returns the caller's in-app feed preference (absent = enabled).
func (in *Inbox) GetPrefs(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	enabled := true
	err := in.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT in_app_enabled FROM notification_user_prefs WHERE user_id=$1`, userID).Scan(&enabled)
		if e == pgx.ErrNoRows {
			enabled = true
			return nil
		}
		return e
	})
	return enabled, err
}

// SetPrefs upserts the caller's own in-app feed preference (scoped to this user + tenant).
func (in *Inbox) SetPrefs(ctx context.Context, tenantID, userID uuid.UUID, enabled bool) error {
	return in.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO notification_user_prefs (tenant_id, user_id, in_app_enabled) VALUES ($1,$2,$3)
			 ON CONFLICT (tenant_id, user_id) DO UPDATE SET in_app_enabled=$3, updated_at=now()`,
			tenantID, userID, enabled)
		return e
	})
}

// --- HTTP ---

// InboxHandler is the authenticated per-user inbox surface. Every method derives the user from the session
// Principal — a caller can only ever act on their OWN inbox.
type InboxHandler struct{ inbox *Inbox }

// NewInboxHandler builds the handler.
func NewInboxHandler(in *Inbox) *InboxHandler { return &InboxHandler{inbox: in} }

// List handles GET /notify/inbox?unread=1&limit=50 — the caller's own feed + unread count.
func (h *InboxHandler) List(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	onlyUnread := r.URL.Query().Get("unread") == "1" || r.URL.Query().Get("unread") == "true"
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := h.inbox.List(r.Context(), p.TenantID, p.UserID, onlyUnread, limit)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not read inbox"))
		return
	}
	unread, err := h.inbox.UnreadCount(r.Context(), p.TenantID, p.UserID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not read inbox"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"notifications": items, "unread_count": unread})
}

// UnreadCount handles GET /notify/inbox/unread-count.
func (h *InboxHandler) UnreadCount(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	n, err := h.inbox.UnreadCount(r.Context(), p.TenantID, p.UserID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not read inbox"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]int{"unread_count": n})
}

// MarkRead handles POST /notify/inbox/{id}/read.
func (h *InboxHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid notification id"))
		return
	}
	if err := h.inbox.MarkRead(r.Context(), p.TenantID, p.UserID, id); err != nil {
		httpx.Error(w, httpx.ErrInternal("could not update notification"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// MarkAllRead handles POST /notify/inbox/read-all.
func (h *InboxHandler) MarkAllRead(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	n, err := h.inbox.MarkAllRead(r.Context(), p.TenantID, p.UserID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not update notifications"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]int{"marked_read": n})
}

// GetPrefs handles GET /notify/inbox/prefs.
func (h *InboxHandler) GetPrefs(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	enabled, err := h.inbox.GetPrefs(r.Context(), p.TenantID, p.UserID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not read preferences"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]bool{"in_app_enabled": enabled})
}

// SetPrefs handles PUT /notify/inbox/prefs {in_app_enabled}.
func (h *InboxHandler) SetPrefs(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		InAppEnabled bool `json:"in_app_enabled"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.inbox.SetPrefs(r.Context(), p.TenantID, p.UserID, in.InAppEnabled); err != nil {
		httpx.Error(w, httpx.ErrInternal("could not save preferences"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]bool{"in_app_enabled": in.InAppEnabled})
}
