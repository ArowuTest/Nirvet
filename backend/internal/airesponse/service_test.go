package airesponse

// S2b i3 accept tests (DB-free, mutation-sensitive). These prove the gate's non-negotiable #1 at the promotion
// boundary: the AI PROPOSES, a HUMAN promotes. Concretely — no run (soar.Run) is ever created unless a soc_manager+
// accepts a PENDING proposal whose enacting playbook actually contains the proposed action. Each guard is asserted by
// counting soar.Run calls: proposal ≠ execution.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/ai"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/google/uuid"
)

type fakeProposals struct {
	prop      *ai.Proposal
	getErr    error
	markErr   error
	markedRun *uuid.UUID
	markCalls int
}

func (f *fakeProposals) GetProposal(_ context.Context, _ auth.Principal, _ uuid.UUID) (*ai.Proposal, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	p := *f.prop // copy so the usecase's mutation doesn't bleed into the fake
	return &p, nil
}

func (f *fakeProposals) MarkProposalAccepted(_ context.Context, _ auth.Principal, _, runID uuid.UUID) error {
	f.markCalls++
	f.markedRun = &runID
	return f.markErr
}

type fakeRunner struct {
	pb       *soar.Playbook
	pbErr    error
	run      *soar.PlaybookRun
	runErr   error
	runCalls int
}

func (f *fakeRunner) GetPlaybook(_ context.Context, _, _ uuid.UUID) (*soar.Playbook, error) {
	return f.pb, f.pbErr
}

func (f *fakeRunner) Run(_ context.Context, _ auth.Principal, _ uuid.UUID, _ *uuid.UUID) (*soar.PlaybookRun, error) {
	f.runCalls++
	if f.runErr != nil {
		return nil, f.runErr
	}
	return f.run, nil
}

func pendingProp(action string) *ai.Proposal {
	return &ai.Proposal{ID: uuid.New(), IncidentRef: uuid.New(), Status: "pending", RecommendedAction: action}
}

func playbookWith(action string) *soar.Playbook {
	return &soar.Playbook{ID: uuid.New(), Steps: []soar.Step{{Name: "s", Action: action}}}
}

func manager() auth.Principal {
	return auth.Principal{UserID: uuid.New(), TenantID: uuid.New(), Role: auth.RoleSOCManager}
}
func analyst() auth.Principal {
	return auth.Principal{UserID: uuid.New(), TenantID: uuid.New(), Role: auth.RoleAnalystT1}
}

// The AI proposes; it never runs. An analyst (below soc_manager) CANNOT promote a proposal — no run is created.
// Mutation-sensitive: drop the in-service role floor and an analyst reaches soar.Run.
func TestAccept_AnalystCannotPromote_NoRun(t *testing.T) {
	pr := &fakeProposals{prop: pendingProp("isolate_host")}
	rn := &fakeRunner{pb: playbookWith("isolate_host"), run: &soar.PlaybookRun{ID: uuid.New(), Status: soar.RunPendingApproval}}
	s := NewService(pr, rn)
	if _, err := s.Accept(context.Background(), analyst(), pr.prop.ID, rn.pb.ID); err == nil {
		t.Fatal("an analyst must not be able to accept (promote) a proposal")
	}
	if rn.runCalls != 0 {
		t.Fatalf("proposal≠execution: a forbidden accept must create no run; got %d run calls", rn.runCalls)
	}
	if pr.markCalls != 0 {
		t.Fatal("a forbidden accept must record no acceptance")
	}
}

// Happy path: a soc_manager promotes a pending proposal → soar.Run (the EXISTING entry, all gates) is called exactly
// once and the proposal is marked accepted with the created run id.
func TestAccept_ManagerPromotes_RunsOnceAndMarks(t *testing.T) {
	pr := &fakeProposals{prop: pendingProp("isolate_host")}
	runID := uuid.New()
	rn := &fakeRunner{pb: playbookWith("isolate_host"), run: &soar.PlaybookRun{ID: runID, Status: soar.RunPendingApproval}}
	s := NewService(pr, rn)
	res, err := s.Accept(context.Background(), manager(), pr.prop.ID, rn.pb.ID)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if rn.runCalls != 1 {
		t.Fatalf("expected exactly one run through the existing soar entry, got %d", rn.runCalls)
	}
	if pr.markCalls != 1 || pr.markedRun == nil || *pr.markedRun != runID {
		t.Fatalf("the proposal must be marked accepted with the created run id")
	}
	if res.RunID != runID || res.Status != string(soar.RunPendingApproval) {
		t.Fatalf("result must carry the created run id + status; got %+v", res)
	}
}

// Accept must run WHAT THE AI PROPOSED: if the senior-selected playbook does not contain the proposed action, accept
// is rejected and NO run is created. Mutation-sensitive: drop the action-match check → an unrelated playbook runs.
func TestAccept_PlaybookMustEnactProposedAction_NoRun(t *testing.T) {
	pr := &fakeProposals{prop: pendingProp("isolate_host")}
	rn := &fakeRunner{pb: playbookWith("disable_user"), run: &soar.PlaybookRun{ID: uuid.New()}}
	s := NewService(pr, rn)
	if _, err := s.Accept(context.Background(), manager(), pr.prop.ID, rn.pb.ID); err == nil {
		t.Fatal("accept must reject a playbook that does not enact the proposed action")
	}
	if rn.runCalls != 0 {
		t.Fatalf("proposal≠execution: no run may be created for a mismatched playbook; got %d", rn.runCalls)
	}
}

// A non-pending proposal (already accepted/rejected) cannot be promoted → no run (double-promotion guard at the door).
func TestAccept_NonPending_NoRun(t *testing.T) {
	pr := &fakeProposals{prop: &ai.Proposal{ID: uuid.New(), IncidentRef: uuid.New(), Status: "accepted", RecommendedAction: "isolate_host"}}
	rn := &fakeRunner{pb: playbookWith("isolate_host"), run: &soar.PlaybookRun{ID: uuid.New()}}
	s := NewService(pr, rn)
	if _, err := s.Accept(context.Background(), manager(), pr.prop.ID, rn.pb.ID); err == nil {
		t.Fatal("a non-pending proposal must not be promotable")
	}
	if rn.runCalls != 0 {
		t.Fatalf("no run may be created for a non-pending proposal; got %d", rn.runCalls)
	}
}

func TestPlaybookHasAction(t *testing.T) {
	pb := &soar.Playbook{Steps: []soar.Step{{Action: "isolate_host"}, {Action: "notify"}}}
	if !playbookHasAction(pb, "ISOLATE_HOST ") {
		t.Fatal("case/space-insensitive match expected")
	}
	if playbookHasAction(pb, "disable_user") {
		t.Fatal("must not match an absent action")
	}
}
