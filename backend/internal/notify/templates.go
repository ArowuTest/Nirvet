package notify

import (
	"context"
	"regexp"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Template is a notification template (COMM-007). Global (tenant nil) or tenant-custom; per channel and
// locale (COMM-008).
type Template struct {
	ID       uuid.UUID  `json:"id"`
	TenantID *uuid.UUID `json:"tenant_id,omitempty"`
	Key      string     `json:"key"`
	Channel  string     `json:"channel"`
	Locale   string     `json:"locale"`
	Subject  string     `json:"subject"`
	Body     string     `json:"body"`
	Enabled  bool       `json:"enabled"`
}

// Rendered is a template with its placeholders filled.
type Rendered struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// varRe matches {{ name }} placeholders (letters, digits, underscore).
var varRe = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_]+)\s*\}\}`)

// renderString substitutes {{var}} with vars[var] (missing vars render empty).
func renderString(tmpl string, vars map[string]string) string {
	return varRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		name := varRe.FindStringSubmatch(m)[1]
		return vars[name]
	})
}

// TemplateRepo persists notification templates + settings (tenant-scoped, with global read).
type TemplateRepo struct{ db *database.DB }

// NewTemplateRepo builds the repository.
func NewTemplateRepo(db *database.DB) *TemplateRepo { return &TemplateRepo{db: db} }

// best resolves the template for (key, channel, locale): prefers an exact locale, then 'en', and a
// tenant-owned row over a global one. Channel 'any' templates match when no channel-specific one exists.
func (r *TemplateRepo) best(ctx context.Context, tenantID uuid.UUID, key, channel, locale string) (*Template, error) {
	var t Template
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, key, channel, locale, subject, body, enabled
			   FROM notification_templates
			  WHERE key=$1 AND enabled=true
			    AND (channel=$2 OR channel='any')
			  ORDER BY (locale=$3) DESC, (locale='en') DESC,
			           (tenant_id IS NOT NULL) DESC, (channel=$2) DESC
			  LIMIT 1`, key, channel, locale).
			Scan(&t.ID, &t.TenantID, &t.Key, &t.Channel, &t.Locale, &t.Subject, &t.Body, &t.Enabled)
	})
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *TemplateRepo) list(ctx context.Context, tenantID uuid.UUID) ([]Template, error) {
	var out []Template
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, key, channel, locale, subject, body, enabled
			   FROM notification_templates ORDER BY key, channel, locale`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t Template
			if err := rows.Scan(&t.ID, &t.TenantID, &t.Key, &t.Channel, &t.Locale, &t.Subject, &t.Body, &t.Enabled); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

func (r *TemplateRepo) upsert(ctx context.Context, tenantID uuid.UUID, t Template) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO notification_templates (tenant_id, key, channel, locale, subject, body, enabled, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7, now())
			 ON CONFLICT (tenant_id, key, channel, locale) DO UPDATE SET
			   subject=EXCLUDED.subject, body=EXCLUDED.body, enabled=EXCLUDED.enabled, updated_at=now()`,
			tenantID, t.Key, t.Channel, t.Locale, t.Subject, t.Body, t.Enabled)
		return err
	})
}

// throttleWindow returns the tenant's throttle window in seconds (0 = disabled) and default locale.
func (r *TemplateRepo) settings(ctx context.Context, tenantID uuid.UUID) (windowSeconds int, locale string, err error) {
	locale = "en"
	err = r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT throttle_window_seconds, default_locale FROM notification_settings WHERE tenant_id=$1`, tenantID).
			Scan(&windowSeconds, &locale)
		if e == pgx.ErrNoRows {
			return nil
		}
		return e
	})
	return windowSeconds, locale, err
}

func (r *TemplateRepo) upsertSettings(ctx context.Context, tenantID uuid.UUID, window int, locale string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO notification_settings (tenant_id, throttle_window_seconds, default_locale, updated_at)
			 VALUES ($1,$2,$3, now())
			 ON CONFLICT (tenant_id) DO UPDATE SET throttle_window_seconds=EXCLUDED.throttle_window_seconds,
			   default_locale=EXCLUDED.default_locale, updated_at=now()`,
			tenantID, window, locale)
		return err
	})
}

// recentlyEnqueued reports whether an identical notification (channel, recipient, subject) was enqueued
// within the throttle window — used to de-dupe (COMM-006).
func (r *TemplateRepo) recentlyEnqueued(ctx context.Context, tenantID uuid.UUID, channel, recipient, subject string, windowSeconds int) (bool, error) {
	if windowSeconds <= 0 {
		return false, nil
	}
	n := 0
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM notification_outbox
			  WHERE channel=$1 AND recipient=$2 AND subject=$3
			    AND created_at > now() - make_interval(secs => $4)`,
			channel, recipient, subject, windowSeconds).Scan(&n)
	})
	return n > 0, err
}

// ── Service ─────────────────────────────────────────────────────────────────────────────────────────

// Render resolves and fills the template for (key, channel) using the tenant's default locale (or the
// requested one) and the supplied vars (COMM-007/008). Falls back to (subject=key) if no template.
func (s *Service) Render(ctx context.Context, tenantID uuid.UUID, key, channel, locale string, vars map[string]string) (Rendered, error) {
	if s.templates == nil {
		return Rendered{}, httpx.ErrInternal("templates not available")
	}
	if locale == "" {
		if _, defLocale, err := s.templates.settings(ctx, tenantID); err == nil {
			locale = defLocale
		}
	}
	t, err := s.templates.best(ctx, tenantID, key, channel, locale)
	if err != nil {
		return Rendered{}, httpx.ErrInternal("could not resolve template")
	}
	if t == nil {
		return Rendered{}, httpx.ErrNotFound("no template for " + key + "/" + channel)
	}
	return Rendered{Subject: renderString(t.Subject, vars), Body: renderString(t.Body, vars)}, nil
}

// ListTemplates returns global + tenant templates.
func (s *Service) ListTemplates(ctx context.Context, tenantID uuid.UUID) ([]Template, error) {
	if s.templates == nil {
		return nil, nil
	}
	return s.templates.list(ctx, tenantID)
}

// TemplateInput upserts a tenant template.
type TemplateInput struct {
	Key     string `json:"key"`
	Channel string `json:"channel"`
	Locale  string `json:"locale"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Enabled *bool  `json:"enabled"`
}

// UpsertTemplate stores a tenant template (COMM-007).
func (s *Service) UpsertTemplate(ctx context.Context, tenantID uuid.UUID, in TemplateInput) error {
	if s.templates == nil {
		return httpx.ErrInternal("templates not available")
	}
	if in.Key == "" {
		return httpx.ErrBadRequest("template key is required")
	}
	t := Template{Key: in.Key, Channel: defaultStr(in.Channel, "email"), Locale: defaultStr(in.Locale, "en"),
		Subject: in.Subject, Body: in.Body, Enabled: true}
	if in.Enabled != nil {
		t.Enabled = *in.Enabled
	}
	if err := s.templates.upsert(ctx, tenantID, t); err != nil {
		return httpx.ErrInternal("could not save template")
	}
	return nil
}

// SettingsInput configures throttle/locale (COMM-006/008).
type SettingsInput struct {
	ThrottleWindowSeconds int    `json:"throttle_window_seconds"`
	DefaultLocale         string `json:"default_locale"`
}

// UpdateSettings sets the tenant's throttle window + default locale.
func (s *Service) UpdateSettings(ctx context.Context, tenantID uuid.UUID, in SettingsInput) error {
	if s.templates == nil {
		return httpx.ErrInternal("settings not available")
	}
	if in.ThrottleWindowSeconds < 0 || in.ThrottleWindowSeconds > 86400 {
		return httpx.ErrBadRequest("throttle window must be 0-86400 seconds")
	}
	return s.templates.upsertSettings(ctx, tenantID, in.ThrottleWindowSeconds, defaultStr(in.DefaultLocale, "en"))
}

// defaultStr returns v, or def when v is empty.
func defaultStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
