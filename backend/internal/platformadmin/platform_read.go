package platformadmin

// §6.18 #175 Platform-Admin slice B (read-only) — the two genuine read gaps: a LIST for maintenance windows (they
// could be created but never read back — a create-without-read asymmetry) and a consolidated NON-SECRET settings
// snapshot for the admin settings screen. Both are read-only aggregates over existing padmin-readable config; they
// add no mutation surface. Data-repair (which MUTATES platform state) is deliberately NOT here — it is a separate,
// security-sensitive surface that gets its own pre-code gate.

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Window is a maintenance window read model. Active is computed server-side (now within [starts_at, ends_at]).
type Window struct {
	ID                    uuid.UUID `json:"id"`
	Scope                 string    `json:"scope"`
	ScopeRef              string    `json:"scope_ref,omitempty"`
	StartsAt              time.Time `json:"starts_at"`
	EndsAt                time.Time `json:"ends_at"`
	SuppressNotifications bool      `json:"suppress_notifications"`
	PauseSLA              bool      `json:"pause_sla"`
	Banner                string    `json:"banner,omitempty"`
	Active                bool      `json:"active"`
	CreatedAt             time.Time `json:"created_at"`
}

// listWindows reads maintenance windows newest-first (global config; WithSystem). Active is computed in SQL.
func (r *Repository) listWindows(ctx context.Context, limit int) ([]Window, error) {
	var out []Window
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `
			SELECT id, scope, scope_ref, starts_at, ends_at, suppress_notifications, pause_sla, banner,
			       (now() BETWEEN starts_at AND ends_at) AS active, created_at
			  FROM maintenance_windows
			 ORDER BY starts_at DESC
			 LIMIT $1`, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var win Window
			if e := rows.Scan(&win.ID, &win.Scope, &win.ScopeRef, &win.StartsAt, &win.EndsAt,
				&win.SuppressNotifications, &win.PauseSLA, &win.Banner, &win.Active, &win.CreatedAt); e != nil {
				return e
			}
			out = append(out, win)
		}
		return rows.Err()
	})
	return out, err
}

// PlatformSettings is a NON-SECRET operational configuration snapshot for the admin settings screen. It contains
// ONLY names, modes, and counts — never a secret (no JWT secret, master key, provider token, API key, or DSN). The
// static fields are captured once at boot (SettingsBase); the dynamic counts are read per request.
type PlatformSettings struct {
	Environment      string `json:"environment"`
	Instance         string `json:"instance"` // "single-sovereign" — never implies a fleet
	CryptoProvider   string `json:"crypto_provider"`
	CryptoRequireKMS bool   `json:"crypto_require_kms"`
	AIModel          string `json:"ai_model"`
	EventBackend     string `json:"event_store_backend"`
	QueueBackend     string `json:"queue_backend"`
	BlobBackend      string `json:"blob_backend"`
	CacheMode        string `json:"cache_mode"`
	// dynamic (per-request)
	FlagCount               int `json:"flag_count"`
	ActiveMaintenanceCount  int `json:"active_maintenance_windows"`
	MaintenanceWindowsTotal int `json:"maintenance_windows_total"`
}
