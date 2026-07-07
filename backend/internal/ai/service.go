package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Service is the AI copilot. It loads only the tenant's own data (isolation),
// calls the gateway (or falls back offline), and logs every call.
type Service struct {
	gw     *Gateway
	alerts *alert.Service
	db     *database.DB
}

// NewService builds the copilot service.
func NewService(gw *Gateway, alerts *alert.Service, db *database.DB) *Service {
	return &Service{gw: gw, alerts: alerts, db: db}
}

// SummariseAlert produces an evidence-linked summary of an alert for an analyst.
func (s *Service) SummariseAlert(ctx context.Context, p auth.Principal, alertID uuid.UUID) (*Summary, error) {
	a, err := s.alerts.Get(ctx, p.TenantID, alertID) // tenant-scoped retrieval (guardrail)
	if err != nil {
		return nil, err
	}
	evidence := []string{
		"title=" + a.Title,
		"severity=" + a.Severity,
		"source=" + a.Source,
		"actor=" + a.ActorRef,
		"target=" + a.TargetRef,
		"mitre=" + strings.Join(a.MITRE, ","),
		"status=" + string(a.Status),
	}
	userContent := "Alert evidence:\n- " + strings.Join(evidence, "\n- ") +
		"\n\nSummarise what happened, why it matters, and suggested next investigative steps."

	sum := &Summary{Model: s.gw.Model(), Evidence: []string{"alert:" + a.ID.String()}, Assistive: true}
	if a.EventID != nil {
		sum.Evidence = append(sum.Evidence, "event:"+a.EventID.String())
	}

	if s.gw.Available() {
		text, err := s.gw.Complete(ctx, systemPrompt, userContent)
		if err == nil {
			sum.Text = text
			sum.Confidence = "inferred"
		} else {
			sum.Text = fallbackSummary(a)
			sum.Confidence = "observed"
			sum.Model = "offline-fallback (llm error)"
		}
	} else {
		sum.Text = fallbackSummary(a)
		sum.Confidence = "observed"
	}

	// Audit the AI call (model + output size) — guardrail: full logging.
	_ = s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "ai.summarise_alert",
			Target:   "alert:" + a.ID.String(),
			Metadata: map[string]any{"model": sum.Model, "output_chars": len(sum.Text)},
		})
	})
	return sum, nil
}

// fallbackSummary is a deterministic, observed-only summary used when no LLM is
// configured — no inference, just the evidence restated operationally.
func fallbackSummary(a *alert.Alert) string {
	mitre := strings.Join(a.MITRE, ", ")
	if mitre == "" {
		mitre = "n/a"
	}
	return fmt.Sprintf(
		"OBSERVED: %s severity alert %q from %s. Actor: %s. Target: %s. MITRE: %s. Status: %s.\n"+
			"SUGGESTED NEXT STEPS: validate the source event, enrich the actor and target, check for "+
			"related alerts on the same entities, and—if confirmed—raise an incident and run the relevant "+
			"playbook via the approval workflow. (Offline summary: no LLM configured; observed evidence only.)",
		a.Severity, a.Title, a.Source, dash(a.ActorRef), dash(a.TargetRef), mitre, a.Status)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
