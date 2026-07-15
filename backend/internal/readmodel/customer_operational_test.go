package readmodel

// BUG-10: the customer's posture must be derived from ONLY the incidents that audience can see. Before this,
// /customer/risk-score reused the provider-wide SLA summary, so a case parked at a pre-customer-visible stage
// (new/triage) inflated the customer's "open incidents" driver while their own incident list showed nothing —
// a visible contradiction AND a leak of how many cases exist behind the disclosure boundary.

import (
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/google/uuid"
)

func ptime(t time.Time) *time.Time { return &t }

// mkInc builds an incident at a stage with explicit SLA timers.
func mkInc(stage incident.Stage, closedAt, ackDue, ackAt, resolveDue *time.Time) incident.Incident {
	return incident.Incident{
		ID: uuid.New(), Stage: stage, ClosedAt: closedAt,
		AckDueAt: ackDue, AcknowledgedAt: ackAt, ResolveDueAt: resolveDue,
	}
}

func TestCustomerOperationalInput_ExcludesNonCustomerVisibleStages(t *testing.T) {
	now := time.Now()
	past := now.Add(-2 * time.Hour)
	pol := DefaultDisclosurePolicy()

	// Two incidents held at pre-customer-visible stages, both open and both SLA-breaching. The customer's
	// incident list row-gates these away, so they must contribute nothing to the customer's posture.
	hidden := []incident.Incident{
		mkInc(incident.StageNew, nil, ptime(past), nil, ptime(past)),
		mkInc(incident.StageTriage, nil, ptime(past), nil, ptime(past)),
	}
	op := CustomerOperationalInput(hidden, pol, now)
	if op.OpenIncidents != 0 || op.AckBreaching != 0 || op.ResolveBreaching != 0 {
		t.Fatalf("hidden-stage incidents leaked into the customer posture: %+v", op)
	}
}

func TestCustomerOperationalInput_CountsVisibleOpenAndBreaches(t *testing.T) {
	now := time.Now()
	past := now.Add(-2 * time.Hour)
	future := now.Add(2 * time.Hour)
	pol := DefaultDisclosurePolicy()

	// Pick a stage the default policy actually discloses, so this test pins behaviour to the policy rather
	// than to a hard-coded stage name.
	var visible incident.Stage
	for s, ok := range pol.CustomerVisibleStages {
		if ok && s != incident.StageClosed && s != incident.StagePostIncidentReview {
			visible = s
			break
		}
	}
	if visible == "" {
		t.Skip("default policy discloses no open stage")
	}

	incs := []incident.Incident{
		mkInc(visible, nil, ptime(past), nil, ptime(past)),           // open, ack-breaching, resolve-breaching
		mkInc(visible, nil, ptime(future), nil, ptime(future)),       // open, within SLA
		mkInc(visible, nil, ptime(past), ptime(past), ptime(future)), // open, acknowledged → not ack-breaching
		mkInc(incident.StageNew, nil, ptime(past), nil, ptime(past)), // hidden → excluded
	}
	op := CustomerOperationalInput(incs, pol, now)
	if op.OpenIncidents != 3 {
		t.Fatalf("OpenIncidents = %d, want 3 (visible open only)", op.OpenIncidents)
	}
	if op.AckBreaching != 1 {
		t.Fatalf("AckBreaching = %d, want 1 (past ack due AND unacknowledged)", op.AckBreaching)
	}
	if op.ResolveBreaching != 1 {
		t.Fatalf("ResolveBreaching = %d, want 1 (open past resolve due)", op.ResolveBreaching)
	}
}

func TestCustomerOperationalInput_ResolvedLateOnlyWhenClosedAfterDue(t *testing.T) {
	now := time.Now()
	pol := DefaultDisclosurePolicy()
	if !pol.CustomerVisibleStages[incident.StageClosed] {
		t.Skip("default policy does not disclose closed incidents")
	}
	due := now.Add(-3 * time.Hour)
	late := now.Add(-1 * time.Hour) // closed AFTER due
	onTime := now.Add(-4 * time.Hour)

	incs := []incident.Incident{
		mkInc(incident.StageClosed, ptime(late), nil, nil, ptime(due)),   // closed late
		mkInc(incident.StageClosed, ptime(onTime), nil, nil, ptime(due)), // closed on time
		mkInc(incident.StageClosed, ptime(late), nil, nil, nil),          // no resolve_due → not late
	}
	op := CustomerOperationalInput(incs, pol, now)
	if op.OpenIncidents != 0 {
		t.Fatalf("closed incidents counted as open: %d", op.OpenIncidents)
	}
	if op.ResolvedLate != 1 {
		t.Fatalf("ResolvedLate = %d, want 1 (closed_at > resolve_due_at, and only when a due time exists)", op.ResolvedLate)
	}
}
