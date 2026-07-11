package notify

// In-app inbox integration. The load-bearing tests are the SCOPE boundary: a user sees/acts on ONLY their own
// notifications (user boundary), and never another tenant's (tenant boundary). Plus prefs-suppression and mark-all.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/google/uuid"
)

func inboxT(t *testing.T) *Inbox {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return NewInbox(db)
}

// The user + tenant boundary: userB (same tenant) cannot see or mark userA's notification; the same user id in a
// different tenant sees nothing.
func TestInbox_PerUserAndTenantScope(t *testing.T) {
	in := inboxT(t)
	ctx := context.Background()
	tenant, otherTenant := uuid.New(), uuid.New()
	userA, userB := uuid.New(), uuid.New()

	if err := in.NotifyInApp(ctx, tenant, userA, "assignment", "Incident assigned", "INC-1"); err != nil {
		t.Fatalf("notify: %v", err)
	}

	a, _ := in.List(ctx, tenant, userA, false, 50)
	if len(a) != 1 {
		t.Fatalf("userA should see their 1 notification, got %d", len(a))
	}
	if b, _ := in.List(ctx, tenant, userB, false, 50); len(b) != 0 {
		t.Fatalf("userB must NOT see userA's notification (user boundary), got %d", len(b))
	}
	if cross, _ := in.List(ctx, otherTenant, userA, false, 50); len(cross) != 0 {
		t.Fatalf("same user id in another tenant must see nothing (tenant boundary), got %d", len(cross))
	}

	// userB cannot mark userA's notification read (recipient_id guard → 0 rows, non-revealing).
	if err := in.MarkRead(ctx, tenant, userB, a[0].ID); err != nil {
		t.Fatalf("markread (userB): %v", err)
	}
	if uc, _ := in.UnreadCount(ctx, tenant, userA); uc != 1 {
		t.Fatalf("userB must not be able to mark userA's read; userA unread=%d (want 1)", uc)
	}
	// userA marks their own read → unread drops to 0.
	if err := in.MarkRead(ctx, tenant, userA, a[0].ID); err != nil {
		t.Fatalf("markread (userA): %v", err)
	}
	if uc, _ := in.UnreadCount(ctx, tenant, userA); uc != 0 {
		t.Fatalf("after userA reads it, unread should be 0, got %d", uc)
	}
}

// A user who disables their feed receives nothing; re-enabling restores delivery. Prefs are per (tenant,user).
func TestInbox_PrefsSuppressDelivery(t *testing.T) {
	in := inboxT(t)
	ctx := context.Background()
	tenant, user := uuid.New(), uuid.New()

	if err := in.SetPrefs(ctx, tenant, user, false); err != nil {
		t.Fatalf("setprefs off: %v", err)
	}
	if enabled, _ := in.GetPrefs(ctx, tenant, user); enabled {
		t.Fatal("prefs should read back disabled")
	}
	_ = in.NotifyInApp(ctx, tenant, user, "info", "suppressed", "x")
	if items, _ := in.List(ctx, tenant, user, false, 50); len(items) != 0 {
		t.Fatalf("a disabled feed must suppress delivery, got %d", len(items))
	}

	_ = in.SetPrefs(ctx, tenant, user, true)
	_ = in.NotifyInApp(ctx, tenant, user, "info", "delivered", "y")
	if items, _ := in.List(ctx, tenant, user, false, 50); len(items) != 1 {
		t.Fatalf("a re-enabled feed should deliver, got %d", len(items))
	}
}

// mark-all clears the caller's unread set; the only_unread filter then returns empty.
func TestInbox_MarkAllRead(t *testing.T) {
	in := inboxT(t)
	ctx := context.Background()
	tenant, user := uuid.New(), uuid.New()
	for i := 0; i < 3; i++ {
		_ = in.NotifyInApp(ctx, tenant, user, "info", "s", "b")
	}
	if uc, _ := in.UnreadCount(ctx, tenant, user); uc != 3 {
		t.Fatalf("want 3 unread, got %d", uc)
	}
	if n, _ := in.MarkAllRead(ctx, tenant, user); n != 3 {
		t.Fatalf("mark-all should affect 3, got %d", n)
	}
	if uc, _ := in.UnreadCount(ctx, tenant, user); uc != 0 {
		t.Fatalf("want 0 unread after mark-all, got %d", uc)
	}
	if unread, _ := in.List(ctx, tenant, user, true, 50); len(unread) != 0 {
		t.Fatalf("only_unread should be empty after mark-all, got %d", len(unread))
	}
}
