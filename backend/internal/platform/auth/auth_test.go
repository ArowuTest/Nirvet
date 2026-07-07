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
