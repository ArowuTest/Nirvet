// Package notify sends notifications to customers and analysts (SRS §6.16) over
// pluggable channels (email/Teams/Slack/webhook). Outbound customer comms require
// human approval (AI/SOAR guardrail). This build ships a log channel; real
// channels are registered the same way once their credentials are configured.
package notify

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Message is an outbound notification.
type Message struct {
	To       string    `json:"to"`
	Subject  string    `json:"subject"`
	Body     string    `json:"body"`
	Channel  string    `json:"channel"`             // log | email | sms | teams | slack (defaults to log)
	TenantID uuid.UUID `json:"tenant_id,omitempty"` // used by email/sms to resolve the tenant's sender config
}

// Channel delivers a message over one transport.
type Channel interface {
	Key() string
	Send(ctx context.Context, m Message) error
}

// logChannel writes the notification to the structured log (dev/scaffold).
type logChannel struct{ log *slog.Logger }

func (c *logChannel) Key() string { return "log" }
func (c *logChannel) Send(_ context.Context, m Message) error {
	c.log.Info("notification", "channel", "log", "to", m.To, "subject", m.Subject)
	return nil
}

// Service routes messages to registered channels.
type Service struct {
	channels  map[string]Channel
	log       *slog.Logger
	outbox    *OutboxRepository   // durable delivery queue (nil = direct dispatch only)
	senders   *SenderRepo         // per-tenant email/sms sender config (nil = email/sms unavailable)
	cipher    crypto.SecretCipher // vault for sender secrets (nil = email/sms unavailable)
	templates *TemplateRepo       // templates + settings (nil = templates/throttle unavailable)
	linkKey   []byte              // HMAC key for secure expiring links (nil = links unavailable)
}

// WithTemplates wires the template store + notification settings (COMM-006/007/008).
func (s *Service) WithTemplates(repo *TemplateRepo) *Service { s.templates = repo; return s }

// WithLinkKey wires the HMAC key used to sign secure expiring links (COMM-009).
func (s *Service) WithLinkKey(key []byte) *Service { s.linkKey = key; return s }

// EnqueueThrottled enqueues a notification unless an identical one (channel, recipient, subject) was
// enqueued within the tenant's throttle window (COMM-006 de-dup). Returns whether it was enqueued.
// Requires the outbox and template (settings) repos. The SLA path stays on the claim-deduped EnqueueTx.
func (s *Service) EnqueueThrottled(ctx context.Context, tenantID uuid.UUID, channel, recipient, subject, body string) (bool, error) {
	if s.outbox == nil {
		return false, httpx.ErrInternal("outbox not available")
	}
	if s.templates != nil {
		window, _, err := s.templates.settings(ctx, tenantID)
		if err == nil && window > 0 {
			dup, derr := s.templates.recentlyEnqueued(ctx, tenantID, channel, recipient, subject, window)
			if derr == nil && dup {
				return false, nil // throttled
			}
		}
	}
	if err := s.outbox.Enqueue(ctx, tenantID, channel, recipient, subject, body); err != nil {
		return false, err
	}
	return true, nil
}

// NotifyPasswordReset enqueues a password-reset email (G1) via the durable outbox. Best-effort: the link is
// built by iam from the server base URL; if the tenant has no email sender configured the row dead-letters and
// the issuing admin can fall back to the one-time returned link.
func (s *Service) NotifyPasswordReset(ctx context.Context, tenantID uuid.UUID, email, link string) error {
	if s.outbox == nil {
		return httpx.ErrInternal("outbox not available")
	}
	body := "A password reset was requested for your Nirvet account. Use this link to set a new password:\n\n" +
		link + "\n\nThis link expires shortly. If you did not expect this, contact your administrator."
	_, err := s.EnqueueThrottled(ctx, tenantID, "email", email, "Reset your Nirvet password", body)
	return err
}

// NewService builds the dispatcher with the log channel plus the real webhook/Teams/Slack channels
// (§6.16 COMM-001) — HTTP POST over an SSRF-safe client, so an escalation contact or SOAR notify with
// channel=webhook/teams/slack is delivered, not dead-lettered. Email(SMTP)/SMS are deferred to slice B
// (they need per-tenant sender config via the vault); an email/sms row dead-letters until then.
func NewService(log *slog.Logger) *Service {
	s := &Service{channels: map[string]Channel{}, log: log}
	s.register(&logChannel{log: log})
	s.registerHTTPChannels(defaultHTTPClient())
	return s
}

// WithOutbox wires the durable notification outbox, enabling Drain/StartDispatcher
// (at-least-once delivery for enqueued notifications; SRS §6.8/§6.16, R3).
func (s *Service) WithOutbox(repo *OutboxRepository) *Service { s.outbox = repo; return s }

func (s *Service) register(c Channel) { s.channels[c.Key()] = c }

// NotifyIncident sends an incident notification (implements the incident.Notifier
// seam). External customer delivery requires approval; the scaffold uses the log
// channel. tenantID is carried for future per-tenant channel routing.
func (s *Service) NotifyIncident(ctx context.Context, tenantID uuid.UUID, subject, body string) error {
	return s.Dispatch(ctx, Message{Subject: subject, Body: body, Channel: "log"})
}

// Dispatch sends a message via the chosen channel (falls back to log).
func (s *Service) Dispatch(ctx context.Context, m Message) error {
	key := m.Channel
	if key == "" {
		key = "log"
	}
	ch, ok := s.channels[key]
	if !ok {
		return httpx.ErrBadRequest("unknown channel: " + key)
	}
	return ch.Send(ctx, m)
}

// Handler exposes notification endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Test handles POST /notify/test — dispatch a message (default log channel).
func (h *Handler) Test(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var m Message
	if err := httpx.Decode(r, &m); err != nil {
		httpx.Error(w, err)
		return
	}
	m.TenantID = p.TenantID // email/sms resolve the caller tenant's sender config
	if err := h.svc.Dispatch(r.Context(), m); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "dispatched"})
}

// ConfigureSender handles PUT /notify/senders — configure a tenant email/sms sender (COMM-001). The
// secret is vault-encrypted; it is never returned.
func (h *Handler) ConfigureSender(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in SenderInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.ConfigureSender(r.Context(), p.TenantID, in); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "configured"})
}

// ListSenders handles GET /notify/senders — tenant sender configs (secrets omitted).
func (h *Handler) ListSenders(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	xs, err := h.svc.ListSenders(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list senders"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"senders": xs})
}

// ListTemplates handles GET /notify/templates (COMM-007).
func (h *Handler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	xs, err := h.svc.ListTemplates(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list templates"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"templates": xs})
}

// UpsertTemplate handles PUT /notify/templates (COMM-007).
func (h *Handler) UpsertTemplate(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in TemplateInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.UpsertTemplate(r.Context(), p.TenantID, in); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// UpdateSettings handles PUT /notify/settings — throttle window + default locale (COMM-006/008).
func (h *Handler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in SettingsInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.UpdateSettings(r.Context(), p.TenantID, in); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// MintLink handles POST /notify/links — mint a secure expiring link for a resource (COMM-009).
func (h *Handler) MintLink(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		Resource   string `json:"resource"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	token, err := h.svc.GenerateLink(p.TenantID, in.Resource, time.Duration(in.TTLSeconds)*time.Second, time.Now())
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"token": token})
}

// VerifyLink handles GET /notify/links/verify?token= — validate a secure link (COMM-009). Only returns
// the resource when the token's tenant matches the caller's tenant.
func (h *Handler) VerifyLink(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	tid, resource, err := h.svc.VerifyLink(r.URL.Query().Get("token"), time.Now())
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid or expired link"))
		return
	}
	if tid != p.TenantID {
		httpx.Error(w, httpx.ErrForbidden("link belongs to another tenant"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"resource": resource})
}
