package soar

// B4 — cross-tenant isolation END-TO-END proof at the API boundary (reviewer-authored, Fable 5, Jul 18 2026).
//
// Every other isolation test in the tree proves the RLS *mechanism* at the repo/service data layer
// (credresolver, cred_expiry, resolver, billing, asset). B4's gap was different: prove that the two MUTATING
// customer-facing {id} verbs — POST /customer/soar/approvals/{id}/{approve,reject} — cannot be driven across
// a tenant boundary by a real session principal. i.e. a genuine BOLA/IDOR proof, not a data-layer RLS check.
//
// Reviewer API-boundary audit (source-verified) established: both handlers derive the tenant from the SESSION
// principal (p.TenantID), never from the path/body; the {id} is always PAIRED with p.TenantID in the fetch
// (ApproveAsCustomer → GetRun(p.TenantID,id); RejectAsCustomer → rejectFor → GetRun(p.TenantID,id)). These
// tests are the affirmative proof of that contract, each with a TWO-SIDED control so a pass is provably a
// tenant mismatch (not a missing/broken run) and is MUTATION-SENSITIVE (break the pairing → the test goes RED).
//
// DB-gated (testsupport.RequireDSN) — runs in the race-suite CI gate against a Postgres with RLS + the
// nirvet_app non-owner role + all migrations; skips locally when NIRVET_TEST_DATABASE_URL is unset.

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestB4_CrossTenant_ApproveIsolation — the core proof for the APPROVE verb.
//
// ApproveAsCustomer fetches GetRun(p.TenantID, id) BEFORE any policy check, so the discriminator is clean:
//   - attacker (tenant A) approving tenant B's run  → 404 (the tenant-scoped fetch never finds it)
//   - victim   (tenant B) approving its OWN run     → 403 (fetch SUCCEEDS; stopped only by B's default policy)
//
// The 404-vs-403 contrast is what proves the 404 is a TENANT mismatch and not a spurious not-found.
func TestB4_CrossTenant_ApproveIsolation(t *testing.T) {
	db := caDB(t)
	svc := NewService(NewRepository(db))
	ctx := context.Background()

	pA, _ := caTenant(t, db)    // attacker principal, tenant A
	pB, tidB := caTenant(t, db) // victim principal, tenant B
	runB := seedPendingRun(t, db, tidB, ptr(uuid.New()))

	// Adversary: tenant A's customer principal approves tenant B's run by id → must be 404 not-found.
	// MUTATION-SENSITIVE: if GetRun were not scoped to p.TenantID, this call would clear the fetch and
	// return 403 (or execute), flipping this assertion RED — that is the regression this proof catches.
	if _, err := svc.ApproveAsCustomer(ctx, pA, runB); !caStatusIs(err, 404) {
		t.Fatalf("BOLA: tenant A must NOT see tenant B's run (expected 404 not-found); got %v", err)
	}

	// Two-sided control: tenant B's own principal reaches the SAME run — it gets PAST the tenant-scoped
	// fetch and is stopped only by tenant B's default (platform_analyst) policy → 403, proving the run
	// exists and is actionable, so the adversary's 404 above was tenant isolation and nothing else.
	if _, err := svc.ApproveAsCustomer(ctx, pB, runB); !caStatusIs(err, 403) {
		t.Fatalf("control: tenant B must FIND its own run and be policy-stopped (expected 403); got %v", err)
	}
}

// TestB4_CrossTenant_RejectIsolation_AttackerCapabilityEnabled — the stronger adversary model for the REJECT
// verb: the attacker has customer approval ENABLED in their OWN tenant, so they clear RejectAsCustomer's
// policy gate. The only remaining guard is rejectFor's tenant-scoped GetRun. This proves the isolation lives
// in the run fetch, not merely in the policy check.
func TestB4_CrossTenant_RejectIsolation_AttackerCapabilityEnabled(t *testing.T) {
	db := caDB(t)
	svc := NewService(NewRepository(db))
	ctx := context.Background()

	pA, _ := caTenant(t, db)    // attacker, tenant A
	pB, tidB := caTenant(t, db) // victim, tenant B

	// Attacker enables customer approval in tenant A → RejectAsCustomer's policy gate passes for pA, so the
	// tenant-scoped run fetch is the ONLY thing that can stop the cross-tenant reject.
	if _, err := svc.SetCustomerPolicy(ctx, pA, CustomerApprovalPolicy{Authority: AuthorityCustomerApprover, LinkTTLSeconds: 7200, CustomerApproverRef: "attacker@a"}); err != nil {
		t.Fatalf("enable policy on attacker tenant: %v", err)
	}
	// Victim enables it too, so the positive control can genuinely reject its own run.
	if _, err := svc.SetCustomerPolicy(ctx, pB, CustomerApprovalPolicy{Authority: AuthorityCustomerApprover, LinkTTLSeconds: 7200, CustomerApproverRef: "owner@b"}); err != nil {
		t.Fatalf("enable policy on victim tenant: %v", err)
	}

	runB := seedPendingRun(t, db, tidB, ptr(uuid.New()))

	// Adversary clears the policy gate (own tenant enabled) but rejectFor scopes GetRun to pA.TenantID →
	// tenant B's run is not found → 404. A capability granted in one tenant does not reach into another.
	// MUTATION-SENSITIVE: if rejectFor's GetRun dropped the tenant pairing, pA would cancel B's run → RED.
	if _, err := svc.RejectAsCustomer(ctx, pA, runB); !caStatusIs(err, 404) {
		t.Fatalf("BOLA: attacker with own-tenant capability must NOT reject tenant B's run (expected 404); got %v", err)
	}

	// Two-sided control: tenant B's own principal rejects its own run → succeeds and transitions to rejected,
	// proving the run was genuinely rejectable and pA's 404 was tenant isolation.
	got, err := svc.RejectAsCustomer(ctx, pB, runB)
	if err != nil {
		t.Fatalf("control: tenant B must reject its own run; got %v", err)
	}
	if got.Status != RunRejected {
		t.Fatalf("control: tenant B's own run must transition to rejected; got status %s", got.Status)
	}
}
