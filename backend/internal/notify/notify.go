// Package notify sends notifications to customers and analysts (SRS §6.16) over
// pluggable channels (email/Teams/Slack/webhook). Outbound customer comms require
// human approval (AI/SOAR guardrail). This build ships a log channel; real
// channels are registered the same way once their credentials are configured.
package notify

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Message is an outbound notification.
type Message struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Channel string `json:"channel"` // log | email | teams | slack (defaults to log)
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
	channels map[string]Channel
	log      *slog.Logger
}

// NewService builds the dispatcher with the default log channel.
func NewService(log *slog.Logger) *Service {
	s := &Service{channels: map[string]Channel{}, log: log}
	s.register(&logChannel{log: log})
	// TODO: register email(SMTP)/teams/slack channels when their creds are set.
	return s
}

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
	_, _ = auth.PrincipalFrom(r.Context())
	var m Message
	if err := httpx.Decode(r, &m); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.Dispatch(r.Context(), m); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "dispatched"})
}
