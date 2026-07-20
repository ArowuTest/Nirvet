package ai

// S2b i3 proposal-validation tests (DB-free): the action VOCABULARY is constrained to the tenant's catalog and the
// validator fails CLOSED when unwired — the two guards the gate (§3) requires so the AI can never propose an action
// the catalog + authority model doesn't already govern. All reach only the pre-DB validation path.

import (
	"context"
	"errors"
	"testing"

	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

// stubIncidents satisfies Incidents with a permissive Get (a real incident in any tenant) so CreateProposal reaches
// the action-catalog validation without a DB. err != nil simulates a foreign/absent incident.
type stubIncidents struct{ err error }

func (s stubIncidents) Get(_ context.Context, _, id uuid.UUID) (*incident.Incident, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &incident.Incident{ID: id, Title: "t", Severity: "high", Stage: "triage"}, nil
}

// stubCatalog satisfies ActionCatalogReader with a fixed valid-key set.
type stubCatalog struct {
	keys map[string]bool
	err  error
}

func (s stubCatalog) ValidActionKeys(_ context.Context, _ uuid.UUID) (map[string]bool, error) {
	return s.keys, s.err
}

func baseProposalInput() ProposalInput {
	return ProposalInput{IncidentRef: uuid.New(), RecommendedAction: "isolate_host", RiskClass: "high"}
}

// The action vocabulary is constrained to the catalog: an action the catalog doesn't govern is rejected BEFORE any
// row is written. Mutation-sensitive — remove the catalog check and this passes an ungoverned action.
func TestCreateProposal_RejectsUnknownAction(t *testing.T) {
	s := &Service{incidents: stubIncidents{}, actionCatalog: stubCatalog{keys: map[string]bool{"disable_user": true}}}
	_, err := s.CreateProposal(context.Background(), auth.Principal{TenantID: uuid.New(), UserID: uuid.New()}, baseProposalInput())
	if err == nil {
		t.Fatal("an action absent from the catalog must be rejected (constrained vocabulary)")
	}
}

// Fail-closed: with no catalog validator wired, CreateProposal REFUSES — an ungoverned action must never slip in on a
// misconfigured deploy; it does not default-allow.
func TestCreateProposal_FailsClosedWhenCatalogUnwired(t *testing.T) {
	s := &Service{incidents: stubIncidents{}} // actionCatalog nil
	_, err := s.CreateProposal(context.Background(), auth.Principal{TenantID: uuid.New(), UserID: uuid.New()}, baseProposalInput())
	if err == nil {
		t.Fatal("an unwired catalog validator must fail closed, not allow the proposal")
	}
}

func TestCreateProposal_RejectsInvalidRisk(t *testing.T) {
	in := baseProposalInput()
	in.RiskClass = "catastrophic"
	s := &Service{incidents: stubIncidents{}, actionCatalog: stubCatalog{keys: map[string]bool{"isolate_host": true}}}
	if _, err := s.CreateProposal(context.Background(), auth.Principal{TenantID: uuid.New()}, in); err == nil {
		t.Fatal("an invalid risk_class must be rejected")
	}
}

func TestCreateProposal_RejectsEmptyAction(t *testing.T) {
	in := baseProposalInput()
	in.RecommendedAction = "  "
	s := &Service{}
	if _, err := s.CreateProposal(context.Background(), auth.Principal{TenantID: uuid.New()}, in); err == nil {
		t.Fatal("an empty recommended_action must be rejected")
	}
}

// A foreign/absent incident ref is rejected — never persist a proposal grounded in an incident the caller can't see.
func TestCreateProposal_RejectsUnknownIncident(t *testing.T) {
	s := &Service{incidents: stubIncidents{err: errors.New("not found")},
		actionCatalog: stubCatalog{keys: map[string]bool{"isolate_host": true}}}
	if _, err := s.CreateProposal(context.Background(), auth.Principal{TenantID: uuid.New()}, baseProposalInput()); err == nil {
		t.Fatal("a proposal against a non-existent incident must be rejected")
	}
}

func TestBoundCitations(t *testing.T) {
	out := boundCitations([]string{" INC ", "", "ALERT-1"})
	if len(out) != 2 || out[0] != "INC" || out[1] != "ALERT-1" {
		t.Fatalf("empties dropped + trimmed expected, got %#v", out)
	}
	many := make([]string, maxProposalCitations+10)
	for i := range many {
		many[i] = "X"
	}
	if got := boundCitations(many); len(got) != maxProposalCitations {
		t.Fatalf("citations must be capped at %d, got %d", maxProposalCitations, len(got))
	}
}
