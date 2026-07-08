package incident

import (
	"testing"
	"time"
)

func TestSLAFor(t *testing.T) {
	if slaFor("critical").ack != 15*time.Minute {
		t.Fatal("critical ack target should be 15m")
	}
	if slaFor("HIGH").ack != 30*time.Minute {
		t.Fatal("severity match must be case-insensitive")
	}
	// Unknown / blank severity must default to medium (never leave a case without SLA).
	if slaFor("").resolve != slaFor("medium").resolve {
		t.Fatal("blank severity should default to the medium SLA")
	}
	if slaFor("nonsense").ack != slaFor("medium").ack {
		t.Fatal("unknown severity should default to the medium SLA")
	}
}

func TestComputeBreach(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ackDue := base.Add(15 * time.Minute)
	resDue := base.Add(4 * time.Hour)
	mk := func() *Incident { return &Incident{AckDueAt: &ackDue, ResolveDueAt: &resDue} }
	at := func(d time.Duration) *time.Time { t := base.Add(d); return &t }

	// Acknowledged on time, still open before the resolve deadline → no breach.
	i := mk()
	i.AcknowledgedAt = at(5 * time.Minute)
	computeBreach(i, base.Add(10*time.Minute))
	if i.AckBreached || i.ResolveBreached {
		t.Fatal("on-time ack, open-before-due: expected no breach")
	}

	// Unacknowledged past the ack deadline → ack breach.
	i = mk()
	computeBreach(i, base.Add(20*time.Minute))
	if !i.AckBreached {
		t.Fatal("unacknowledged past due must breach ack")
	}

	// Acknowledged late → ack breach.
	i = mk()
	i.AcknowledgedAt = at(20 * time.Minute)
	computeBreach(i, base.Add(21*time.Minute))
	if !i.AckBreached {
		t.Fatal("late acknowledgement must breach ack")
	}

	// Open past the resolve deadline → resolve breach.
	i = mk()
	i.AcknowledgedAt = at(5 * time.Minute)
	computeBreach(i, base.Add(5*time.Hour))
	if !i.ResolveBreached {
		t.Fatal("open past resolve due must breach resolve")
	}

	// Closed before the resolve deadline → no resolve breach even if 'now' is later.
	i = mk()
	i.AcknowledgedAt = at(5 * time.Minute)
	i.ClosedAt = at(3 * time.Hour)
	computeBreach(i, base.Add(6*time.Hour))
	if i.ResolveBreached {
		t.Fatal("closed before due must not breach resolve")
	}

	// No due-times (pre-SLA row) → never breached.
	i = &Incident{}
	computeBreach(i, base.Add(100*time.Hour))
	if i.AckBreached || i.ResolveBreached {
		t.Fatal("an incident with no SLA due-times must never be flagged breached")
	}
}
