package auth

// S1 force-MFA — unit tests (no DB): the MFAPending claim survives the token round-trip, and RequireMFAComplete
// (the grace-session restriction, gate §5 "grace scope is restricted") blocks an MFAPending principal while letting
// a full session through. The enroll/activate routes are wired WITHOUT this middleware (authedMFAEnroll in main.go)
// so a grace session can still reach them — the one intended hole.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMFAPendingClaimRoundTrips(t *testing.T) {
	m := NewManager("test-secret-0123456789-abcdefghij", "nirvet", time.Hour)
	tok, err := m.IssueWithTTL(Principal{UserID: uuid.New(), TenantID: uuid.New(), Role: RoleCustomerViewer, MFAPending: true}, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	p, err := m.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !p.MFAPending {
		t.Fatal("MFAPending must survive Issue→Verify (else the grace restriction is lost on every request)")
	}
	// A full session must NOT carry MFAPending.
	tok2, _ := m.IssueWithTTL(Principal{UserID: uuid.New(), TenantID: uuid.New(), Role: RoleCustomerViewer}, time.Hour)
	p2, _ := m.Verify(tok2)
	if p2.MFAPending {
		t.Fatal("a full session must not carry MFAPending")
	}
}

func TestRequireMFAComplete_BlocksGraceAllowsFull(t *testing.T) {
	reached := false
	h := RequireMFAComplete()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	// Grace (MFAPending) session → 403, never reaches the handler.
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{UserID: uuid.New(), MFAPending: true}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("grace session must be 403, got %d", rr.Code)
	}
	if reached {
		t.Fatal("grace session must NOT reach the handler")
	}

	// Full session → passes through.
	reached = false
	req2 := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req2 = req2.WithContext(WithPrincipal(req2.Context(), Principal{UserID: uuid.New()}))
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK || !reached {
		t.Fatalf("full session must pass, got code=%d reached=%v", rr2.Code, reached)
	}
}
