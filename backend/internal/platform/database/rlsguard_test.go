package database

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestAssertRLSConstrainedRole: the non-owner app role passes; an owner/superuser role is refused.
func TestAssertRLSConstrainedRole(t *testing.T) {
	appDSN := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if appDSN == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run the RLS-role guard test")
	}
	ctx := context.Background()

	// Positive: nirvet_app is a non-owner, non-superuser role → RLS-constrained → passes.
	db, err := Connect(ctx, appDSN)
	if err != nil {
		t.Fatalf("connect app role: %v", err)
	}
	defer db.Close()
	if err := db.AssertRLSConstrainedRole(ctx); err != nil {
		t.Fatalf("the non-owner app role must PASS the RLS-constrained guard: %v", err)
	}

	// Negative: the owner/superuser role can bypass RLS (owner_bypass / rolsuper) → must be REFUSED.
	ownerDSN := os.Getenv("NIRVET_OWNER_TEST_DATABASE_URL")
	if ownerDSN == "" {
		t.Skip("set NIRVET_OWNER_TEST_DATABASE_URL (owner/superuser DSN) to exercise the refuse path")
	}
	odb, err := Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("connect owner role: %v", err)
	}
	defer odb.Close()
	err = odb.AssertRLSConstrainedRole(ctx)
	if err == nil {
		t.Fatal("the owner/superuser role must be REFUSED by the guard (would silently disable isolation)")
	}
	if !strings.Contains(err.Error(), "bypass RLS") {
		t.Fatalf("the refusal must name the RLS-bypass problem, got: %v", err)
	}
}
