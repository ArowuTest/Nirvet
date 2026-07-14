package ai_test

// B1 AI copilot — DB-gated integration test. With no provider configured (Available()=false) the copilot must
// still persist the conversation and return a truthful "not configured" reply (no egress, no fabrication). Also
// asserts session ownership isolation: a different user in the same tenant cannot read another analyst's session.
// Skips when no test DSN is set (testsupport.RequireDSN).

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArowuTest/nirvet/internal/ai"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
)

func TestCopilot_PersistsAndIsolates(t *testing.T) {
	ctx := context.Background()
	db, err := database.Connect(ctx, testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "cop-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// No provider configured → the gateway reports Available()=false → fallback path (no egress).
	svc := ai.NewService(ai.NewGateway("", ""), nil, db)

	analyst := auth.Principal{UserID: uuid.New(), TenantID: tn.ID, Email: "a@corp.test"}
	peer := auth.Principal{UserID: uuid.New(), TenantID: tn.ID, Email: "b@corp.test"}

	sess, err := svc.StartCopilotSession(ctx, analyst, "brute force look", nil)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}

	turn, err := svc.Ask(ctx, analyst, sess.ID, "what is happening on host-01?")
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if turn.Role != "assistant" || !strings.Contains(turn.Content, "not configured") {
		t.Fatalf("expected 'not configured' assistant reply, got: %+v", turn)
	}

	// GetSession returns both turns in order (user question, then assistant reply).
	got, turns, err := svc.GetCopilotSession(ctx, analyst, sess.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if got.ID != sess.ID || len(turns) != 2 {
		t.Fatalf("want 2 turns, got %d (%+v)", len(turns), turns)
	}
	if turns[0].Role != "user" || turns[0].Content != "what is happening on host-01?" || turns[1].Role != "assistant" {
		t.Fatalf("turns out of order or wrong: %+v", turns)
	}

	// Ownership isolation: a peer in the same tenant cannot read the analyst's private session.
	if _, _, err := svc.GetCopilotSession(ctx, peer, sess.ID); err == nil {
		t.Fatal("a peer must NOT be able to read another analyst's copilot session")
	}
	// And a peer cannot post into it.
	if _, err := svc.Ask(ctx, peer, sess.ID, "let me in"); err == nil {
		t.Fatal("a peer must NOT be able to post into another analyst's session")
	}

	// The peer's own session list is empty; the analyst's has one.
	if mine, _ := svc.ListCopilotSessions(ctx, analyst); len(mine) != 1 {
		t.Fatalf("analyst should have 1 session, got %d", len(mine))
	}
	if theirs, _ := svc.ListCopilotSessions(ctx, peer); len(theirs) != 0 {
		t.Fatalf("peer should have 0 sessions, got %d", len(theirs))
	}
}
