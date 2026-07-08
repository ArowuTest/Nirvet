package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJWTRoundTrip(t *testing.T) {
	m := NewManager("secret", "nirvet", 15*time.Minute)
	p := Principal{UserID: uuid.New(), TenantID: uuid.New(), Role: RoleAnalystT2, Email: "a@b.c"}
	tok, err := m.Issue(p)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := m.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.UserID != p.UserID || got.TenantID != p.TenantID || got.Role != p.Role || got.Email != p.Email {
		t.Fatalf("principal mismatch: %+v vs %+v", got, p)
	}
}

// TestElevationIDRoundtrip locks the Round-4 M6 plumbing: an elevated token carries its elevation id
// (eid claim) through Issue→Verify so the per-request checker can re-validate the grant; an ordinary
// token carries none.
func TestElevationIDRoundtrip(t *testing.T) {
	m := NewManager("secret", "nirvet", 15*time.Minute)
	eid := uuid.New().String()
	elevated := Principal{UserID: uuid.New(), TenantID: uuid.New(), Role: RoleSOCManager, Email: "e@b.c", ElevationID: eid}
	tok, err := m.IssueWithTTL(elevated, time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := m.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.ElevationID != eid {
		t.Fatalf("elevation id not carried: got %q want %q", got.ElevationID, eid)
	}
	// An ordinary token has no elevation id.
	ord, _ := m.Issue(Principal{UserID: uuid.New(), TenantID: uuid.New(), Role: RoleAnalystT1})
	if g, _ := m.Verify(ord); g.ElevationID != "" {
		t.Fatalf("ordinary token must not carry an elevation id, got %q", g.ElevationID)
	}
}

// TestRoleRank locks the canonical ordering used by the SOAR approver floor + break-glass tier cap.
func TestRoleRank(t *testing.T) {
	if RoleRank(RoleAnalystT1) >= RoleRank(RoleSOCManager) {
		t.Fatal("analyst_t1 must rank below soc_manager")
	}
	if RoleRank(RoleSOCManager) >= RoleRank(RolePlatformAdmin) {
		t.Fatal("soc_manager must rank below platform_admin")
	}
	if RoleRank(RoleCustomerViewer) != 0 || RoleRank(Role("wizard")) != 0 {
		t.Fatal("viewer and unknown roles must rank 0")
	}
}

func TestVerifyWrongSecret(t *testing.T) {
	issuer := NewManager("secret-A", "nirvet", 15*time.Minute)
	verifier := NewManager("secret-B", "nirvet", 15*time.Minute)
	tok, _ := issuer.Issue(Principal{UserID: uuid.New(), TenantID: uuid.New(), Role: RoleAnalystT1})
	if _, err := verifier.Verify(tok); err == nil {
		t.Fatal("token signed with a different secret must not verify")
	}
}

func TestVerifyWrongIssuer(t *testing.T) {
	issuer := NewManager("secret", "attacker", 15*time.Minute)
	verifier := NewManager("secret", "nirvet", 15*time.Minute)
	tok, _ := issuer.Issue(Principal{UserID: uuid.New(), TenantID: uuid.New(), Role: RoleAnalystT1})
	if _, err := verifier.Verify(tok); err == nil {
		t.Fatal("token with wrong issuer must not verify")
	}
}

func TestVerifyExpired(t *testing.T) {
	m := NewManager("secret", "nirvet", -1*time.Minute) // already expired
	tok, _ := m.Issue(Principal{UserID: uuid.New(), TenantID: uuid.New(), Role: RoleAnalystT1})
	if _, err := m.Verify(tok); err == nil {
		t.Fatal("expired token must not verify")
	}
}

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("Sup3rSecret!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash == "Sup3rSecret!" {
		t.Fatal("hash must not equal plaintext")
	}
	if !ComparePassword(hash, "Sup3rSecret!") {
		t.Fatal("correct password must match")
	}
	if ComparePassword(hash, "wrong") {
		t.Fatal("wrong password must not match")
	}
}

func TestIsProviderRole(t *testing.T) {
	if !IsProviderRole(RoleAnalystT2) {
		t.Fatal("analyst is a provider role")
	}
	if IsProviderRole(RoleCustomerViewer) {
		t.Fatal("customer viewer is NOT a provider role")
	}
}
