package ai

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Incidents / Assets are the narrow read deps for incident triage (satisfied by
// incident.Service and asset.Service). Optional — nil disables incident triage.
type Incidents interface {
	Get(ctx context.Context, tenantID, id uuid.UUID) (*incident.Incident, error)
}
type Assets interface {
	FindByRefs(ctx context.Context, tenantID uuid.UUID, refs []string) ([]asset.Asset, error)
}

// Service is the AI copilot. It loads only the tenant's own data (isolation),
// calls the gateway (or falls back offline), and logs every call.
type Service struct {
	gw        *Gateway
	alerts    *alert.Service
	incidents Incidents
	assets    Assets
	db        *database.DB
}

// NewService builds the copilot service.
func NewService(gw *Gateway, alerts *alert.Service, db *database.DB) *Service {
	return &Service{gw: gw, alerts: alerts, db: db}
}

// WithIncidentContext wires the incident + asset read paths for incident triage.
func (s *Service) WithIncidentContext(i Incidents, a Assets) *Service {
	s.incidents = i
	s.assets = a
	return s
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

// TriageIncident produces an assistive triage assessment for an incident, grounded in
// its own alerts, affected assets (with criticality) and SLA status. Assistive only:
// it recommends steps to run via the approval workflow, never executes. Tenant-scoped
// retrieval + full audit (§6.12 guardrails).
func (s *Service) TriageIncident(ctx context.Context, p auth.Principal, incidentID uuid.UUID) (*Summary, error) {
	if s.incidents == nil {
		return nil, httpx.ErrBadRequest("incident triage is not available")
	}
	inc, err := s.incidents.Get(ctx, p.TenantID, incidentID) // computes SLA breach flags
	if err != nil {
		return nil, err
	}
	alerts, _ := s.alerts.ListByIncident(ctx, p.TenantID, incidentID)

	// Distinct entity refs + ATT&CK techniques across the incident's alerts.
	var refs []string
	seenRef := map[string]bool{}
	techSet := map[string]bool{}
	for _, a := range alerts {
		for _, r := range []string{a.TargetRef, a.ActorRef} {
			if r != "" && !seenRef[r] {
				seenRef[r] = true
				refs = append(refs, r)
			}
		}
		for _, m := range a.MITRE {
			if m != "" {
				techSet[m] = true
			}
		}
	}
	techniques := make([]string, 0, len(techSet))
	for t := range techSet {
		techniques = append(techniques, t)
	}
	sort.Strings(techniques)

	var assets []asset.Asset
	if s.assets != nil {
		assets, _ = s.assets.FindByRefs(ctx, p.TenantID, refs)
	}

	facts := triageFacts(inc, alerts, assets, techniques)
	userContent := "Incident evidence:\n- " + strings.Join(facts, "\n- ") +
		"\n\nProvide a concise triage assessment: what this incident appears to be, why it matters " +
		"(consider severity, SLA status and affected-asset criticality), and the recommended next steps " +
		"(to be executed by a human via the approval workflow)."

	sum := &Summary{Model: s.gw.Model(), Assistive: true, Evidence: []string{"incident:" + inc.ID.String()}}
	for _, a := range alerts {
		sum.Evidence = append(sum.Evidence, "alert:"+a.ID.String())
	}
	for _, as := range assets {
		sum.Evidence = append(sum.Evidence, "asset:"+as.Ref)
	}

	if s.gw.Available() {
		if text, gerr := s.gw.Complete(ctx, systemPrompt, userContent); gerr == nil {
			sum.Text = text
			sum.Confidence = "inferred"
		} else {
			sum.Text = fallbackTriage(facts)
			sum.Confidence = "observed"
			sum.Model = "offline-fallback (llm error)"
		}
	} else {
		sum.Text = fallbackTriage(facts)
		sum.Confidence = "observed"
	}

	_ = s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "ai.triage_incident",
			Target:   "incident:" + inc.ID.String(),
			Metadata: map[string]any{"model": sum.Model, "output_chars": len(sum.Text)},
		})
	})
	return sum, nil
}

// triageFacts renders the observed facts about an incident used both as the LLM
// context and (verbatim) as the basis of the deterministic offline fallback.
func triageFacts(inc *incident.Incident, alerts []alert.Alert, assets []asset.Asset, techniques []string) []string {
	sla := "on track"
	switch {
	case inc.AckBreached && inc.ResolveBreached:
		sla = "ACK + RESOLVE deadlines breached"
	case inc.AckBreached:
		sla = "ACK deadline breached"
	case inc.ResolveBreached:
		sla = "RESOLVE deadline breached"
	}
	facts := []string{
		"incident=" + inc.Title,
		"severity=" + inc.Severity,
		"stage=" + string(inc.Stage),
		"sla=" + sla,
		fmt.Sprintf("alerts=%d", len(alerts)),
	}
	if len(techniques) > 0 {
		facts = append(facts, "mitre="+strings.Join(techniques, ", "))
	}
	if len(assets) > 0 {
		names := make([]string, 0, len(assets))
		for _, a := range assets {
			names = append(names, fmt.Sprintf("%s(%s)", a.Ref, a.Criticality))
		}
		facts = append(facts, "affected_assets="+strings.Join(names, ", "))
	}
	return facts
}

// fallbackTriage is the deterministic, observed-only triage used when no LLM is
// configured — the evidence restated operationally, with approval-gated next steps.
func fallbackTriage(facts []string) string {
	return "OBSERVED:\n- " + strings.Join(facts, "\n- ") + "\n" +
		"SUGGESTED NEXT STEPS: confirm the correlated alerts, prioritise by affected-asset criticality " +
		"and SLA status, enrich the involved entities, and—if confirmed—run the relevant containment " +
		"playbook via the approval workflow. (Offline triage: no LLM configured; observed evidence only.)"
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
