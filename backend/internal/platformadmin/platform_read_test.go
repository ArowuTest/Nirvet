package platformadmin

// §6.18 #175 slice B (read-only) — maintenance-window LIST read (the read side of CreateWindow), asserting the
// server-computed Active state distinguishes a live window from an already-ended one.

import (
	"context"
	"testing"
	"time"
)

// TestListWindows_ActiveComputed: an active (now within range) window reads Active=true; a past window Active=false.
func TestListWindows_ActiveComputed(t *testing.T) {
	db := paDB(t)
	m := NewMaintenanceService(NewRepository(db))
	ctx := context.Background()
	tid := paTenant(t, db)

	// Active now: started a minute ago, ends in an hour.
	if err := m.CreateWindow(ctx, padminActor(), "tenant", tid.String(),
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), true, false, "active window "+tid.String()); err != nil {
		t.Fatalf("create active: %v", err)
	}
	// Already ended: started 2h ago, ended 1h ago.
	if err := m.CreateWindow(ctx, padminActor(), "tenant", tid.String(),
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), true, false, "past window "+tid.String()); err != nil {
		t.Fatalf("create past: %v", err)
	}

	windows, err := m.ListWindows(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var activeSeen, pastSeen bool
	for _, w := range windows {
		switch w.Banner {
		case "active window " + tid.String():
			activeSeen = true
			if !w.Active {
				t.Fatalf("a currently-live window must read Active=true: %+v", w)
			}
		case "past window " + tid.String():
			pastSeen = true
			if w.Active {
				t.Fatalf("an already-ended window must read Active=false: %+v", w)
			}
		}
	}
	if !activeSeen || !pastSeen {
		t.Fatalf("both windows must appear in the list (active=%v past=%v)", activeSeen, pastSeen)
	}
}
