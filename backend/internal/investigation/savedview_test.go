package investigation

// §6.9 slice B saved-view tests (DB-free): the now-relative window materialisation + the create-time validation that
// runs before any DB touch. The escalation-safety property (a run re-validates for the running actor) is structural —
// RunSavedView delegates to RunHunt, which the existing hunt-query tests already exercise for role + cost ceiling.

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

// toQuery materialises a FRESH now-relative window each run (From = now - lookback, To = now) and carries the
// predicates + limit — so a saved view re-run tomorrow searches tomorrow's window, not a stale absolute one.
func TestSavedView_ToQuery(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	sv := SavedView{
		All:             []Predicate{{Field: "severity", Op: "eq", Value: "high"}},
		LookbackSeconds: 3600,
		Limit:           50,
	}
	q := sv.toQuery(now)
	if !q.To.Equal(now) {
		t.Fatalf("To must be now; got %v", q.To)
	}
	if !q.From.Equal(now.Add(-3600 * time.Second)) {
		t.Fatalf("From must be now-lookback; got %v", q.From)
	}
	if len(q.All) != 1 || q.All[0].Field != "severity" {
		t.Fatalf("predicates must carry through; got %+v", q.All)
	}
	if q.Limit != 50 {
		t.Fatalf("limit must carry through; got %d", q.Limit)
	}
}

// CreateSavedView rejects an empty name and a non-positive lookback BEFORE touching the DB (nil repo is never reached).
func TestCreateSavedView_RejectsEmptyNameAndLookback(t *testing.T) {
	s := &Service{} // nil repo — both cases return before LoadLimits/insert
	p := auth.Principal{TenantID: uuid.New(), UserID: uuid.New()}
	if _, err := s.CreateSavedView(context.Background(), p, SavedViewInput{Name: "  ", LookbackSeconds: 3600}); err == nil {
		t.Fatal("an empty name must be rejected")
	}
	if _, err := s.CreateSavedView(context.Background(), p, SavedViewInput{Name: "x", LookbackSeconds: 0}); err == nil {
		t.Fatal("a non-positive lookback must be rejected")
	}
}
