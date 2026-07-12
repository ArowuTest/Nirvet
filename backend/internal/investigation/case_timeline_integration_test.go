package investigation

// #188 multi-lane case-timeline landing round (DB-gated). Proves the merge: incident-journal entries map to the
// right lanes (evidence/automation/comms/analyst), out-of-window entries are dropped, the result is chronological,
// and the refs cap holds. The forensic event lane is exercised for its guards elsewhere (GetTimeline / hunt); here
// a fake journal reader isolates the merge + lane-mapping + window logic that is NEW.

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

type fakeJournal struct{ entries []CaseJournalEntry }

func (f fakeJournal) CaseJournal(context.Context, uuid.UUID, uuid.UUID) ([]CaseJournalEntry, error) {
	return f.entries, nil
}

func caseTLSetup(t *testing.T, j CaseJournalReader) (*Service, auth.Principal, uuid.UUID) {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "ct-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	svc := NewService(NewRepository(db))
	if j != nil {
		svc = svc.WithCaseJournal(j)
	}
	p := auth.Principal{TenantID: tn.ID, UserID: uuid.New(), Email: "a@b.c", Role: auth.RoleSOCManager}
	return svc, p, uuid.New()
}

func TestCaseTimeline_MergesLanesSortedAndWindowed(t *testing.T) {
	base := time.Now()
	j := fakeJournal{entries: []CaseJournalEntry{
		{At: base.Add(-3 * time.Hour), Kind: "evidence", Visibility: "internal", Note: "collected pcap"},
		{At: base.Add(-2 * time.Hour), Kind: "note", Visibility: "internal", Note: "analyst triage"},
		{At: base.Add(-1 * time.Hour), Kind: "action", Visibility: "internal", Note: "isolated host"},
		{At: base.Add(-30 * time.Minute), Kind: "status", Visibility: "customer", Note: "customer update"},
		{At: base.Add(-100 * time.Hour), Kind: "note", Visibility: "internal", Note: "way out of window"},
	}}
	svc, p, incID := caseTLSetup(t, j)
	from, to := base.Add(-24*time.Hour), base
	tl, err := svc.GetCaseTimeline(context.Background(), p, incID, nil, from, to)
	if err != nil {
		t.Fatalf("case timeline: %v", err)
	}
	if len(tl.Entries) != 4 {
		t.Fatalf("expected 4 in-window entries (the -100h one dropped), got %d", len(tl.Entries))
	}
	wantLanes := []string{"evidence", "analyst", "automation", "comms"}
	for i, e := range tl.Entries {
		if e.Lane != wantLanes[i] {
			t.Fatalf("entry %d lane=%q, want %q (mapping or sort wrong): %+v", i, e.Lane, wantLanes[i], tl.Entries)
		}
		if i > 0 && e.At.Before(tl.Entries[i-1].At) {
			t.Fatalf("entries must be chronological; got %+v", tl.Entries)
		}
	}
}

func TestCaseTimeline_RefsCap(t *testing.T) {
	svc, p, incID := caseTLSetup(t, fakeJournal{})
	refs := make([]string, maxCaseTimelineRefs+1)
	for i := range refs {
		refs[i] = "host:x"
	}
	if _, err := svc.GetCaseTimeline(context.Background(), p, incID, refs, time.Now().Add(-time.Hour), time.Now()); err == nil {
		t.Fatal("expected a 400 for exceeding the case-timeline ref cap")
	}
}

func TestCaseTimeline_JournalOptional(t *testing.T) {
	// No journal wired + no refs → an empty (but valid) timeline; investigation stays usable without incident.
	svc, p, incID := caseTLSetup(t, nil)
	tl, err := svc.GetCaseTimeline(context.Background(), p, incID, nil, time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("journal-optional path errored: %v", err)
	}
	if len(tl.Entries) != 0 {
		t.Fatalf("expected an empty timeline with no journal and no refs, got %d", len(tl.Entries))
	}
}
