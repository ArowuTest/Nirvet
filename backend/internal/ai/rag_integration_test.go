package ai_test

// Copilot completion increment 3 — RAG falsification tests (DB-gated), against GATE_COPILOT_COMPLETION_I3_RAG.md §4.
// These prove the two non-negotiables at the DATABASE boundary, where RLS actually lives:
//   #1 CROSS-TENANT ISOLATION (the crux) — tenant A's retrieval NEVER returns a tenant-B chunk. Mutation-sensitive:
//      drop the WithTenant scope in RetrieveSimilar and the tenant-B assertion goes RED.
//   #2 FIELD-VISIBILITY — a junior analyst's retrieval never surfaces a senior-only chunk; a senior can see it.
//   #6 RETENTION — PurgeCaseEmbeddings drops recall memory, AND the incident FK's ON DELETE CASCADE (mig 0143) purges
//      embeddings when the incident itself is deleted (the RAG can never resurrect deleted data).
//   #9 BOUNDED — retrieval is top-K bounded.
// Requires pgvector (CI runs pgvector/pgvector:pg17; local via deploy/docker-compose.yml). Skips without a test DSN.

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArowuTest/nirvet/internal/ai"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
)

// ragTestTenant creates a tenant + one incident in it, and returns the incident id plus an analyst principal.
func ragTestTenant(t *testing.T, ctx context.Context, db *database.DB, role auth.Role) (uuid.UUID, auth.Principal) {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "rag-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	p := auth.Principal{UserID: uuid.New(), TenantID: tn.ID, Email: "a@corp.test", Role: role}
	inc, err := incident.NewService(incident.NewRepository(db), nil, nil).
		CreateManual(ctx, p, incident.ManualInput{Title: "brute force on host", Severity: "high", Category: "intrusion"})
	if err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	return inc.ID, p
}

// #1 the crux + #2 field-visibility + #9 bounded, all in one two-tenant fixture.
func TestRAG_CrossTenantIsolation_FieldVisibility_Bounded(t *testing.T) {
	ctx := context.Background()
	db, err := database.Connect(ctx, testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	svc := ai.NewService(ai.NewGateway("", ""), nil, db)

	incA, analystA := ragTestTenant(t, ctx, db, auth.RoleAnalystT1)
	incB, analystB := ragTestTenant(t, ctx, db, auth.RoleAnalystT1)
	seniorA := analystA
	seniorA.UserID = uuid.New()
	seniorA.Role = auth.RoleSOCManager // rank 4 > analyst_t1 rank 1

	// Tenant A: an everyone-visible chunk + a senior-only chunk. Tenant B: its own chunk (the cross-tenant probe).
	mustIndex(t, ctx, svc, analystA, incA, "tenantA brute force failed logon host-01 from 10.0.0.5", "analyst_t1")
	mustIndex(t, ctx, svc, seniorA, incA, "tenantA senior-only note: exec mailbox compromised host-01", "soc_manager")
	mustIndex(t, ctx, svc, analystB, incB, "tenantB brute force failed logon host-99 from 10.9.9.9", "analyst_t1")

	// #1 THE CRUX: tenant A's copilot retrieves ONLY tenant-A chunks — never tenant B's. Query shares tokens with both.
	aChunks, err := svc.RetrieveSimilar(ctx, analystA, "brute force failed logon host", 10)
	if err != nil {
		t.Fatalf("retrieve A: %v", err)
	}
	if len(aChunks) == 0 {
		t.Fatal("tenant A must retrieve its own chunk")
	}
	for _, c := range aChunks {
		if strings.Contains(c.Chunk, "tenantB") {
			t.Fatalf("CROSS-TENANT LEAK: tenant A retrieved a tenant-B chunk: %q", c.Chunk)
		}
		if c.IncidentRef != incA {
			t.Fatalf("tenant A retrieved a chunk not from its own incident: ref=%s want=%s", c.IncidentRef, incA)
		}
	}
	// And the reverse: tenant B never sees tenant A.
	bChunks, err := svc.RetrieveSimilar(ctx, analystB, "brute force failed logon host", 10)
	if err != nil {
		t.Fatalf("retrieve B: %v", err)
	}
	for _, c := range bChunks {
		if strings.Contains(c.Chunk, "tenantA") {
			t.Fatalf("CROSS-TENANT LEAK: tenant B retrieved a tenant-A chunk: %q", c.Chunk)
		}
	}

	// #2 FIELD-VISIBILITY: the junior analyst never retrieves the senior-only chunk...
	for _, c := range aChunks {
		if strings.Contains(c.Chunk, "senior-only") {
			t.Fatalf("FIELD-VISIBILITY LEAK: a junior analyst retrieved a soc_manager-only chunk: %q", c.Chunk)
		}
	}
	// ...but a soc_manager in the same tenant can.
	seniorChunks, err := svc.RetrieveSimilar(ctx, seniorA, "senior exec mailbox host", 10)
	if err != nil {
		t.Fatalf("retrieve senior: %v", err)
	}
	var sawSenior bool
	for _, c := range seniorChunks {
		if strings.Contains(c.Chunk, "senior-only") {
			sawSenior = true
		}
	}
	if !sawSenior {
		t.Fatal("a soc_manager must be able to retrieve the senior-only chunk")
	}

	// #9 BOUNDED: k caps the result count. Index several more A chunks, then retrieve with k=2.
	for i := 0; i < 6; i++ {
		mustIndex(t, ctx, svc, analystA, incA, "tenantA brute force attempt variant filler logon host-01", "analyst_t1")
	}
	capped, err := svc.RetrieveSimilar(ctx, analystA, "brute force host", 2)
	if err != nil {
		t.Fatalf("retrieve capped: %v", err)
	}
	if len(capped) > 2 {
		t.Fatalf("retrieval must be top-K bounded: asked k=2, got %d", len(capped))
	}
}

// #6 RETENTION: PurgeCaseEmbeddings drops recall memory; and the incident FK ON DELETE CASCADE purges embeddings when
// the incident itself is deleted — a deleted incident's memory is never retrievable (the RAG can't resurrect it).
func TestRAG_Retention_PurgeAndFKCascade(t *testing.T) {
	ctx := context.Background()
	db, err := database.Connect(ctx, testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	svc := ai.NewService(ai.NewGateway("", ""), nil, db)

	// Explicit purge path.
	incA, analystA := ragTestTenant(t, ctx, db, auth.RoleAnalystT1)
	mustIndex(t, ctx, svc, analystA, incA, "tenantA purge-me brute force host-01", "analyst_t1")
	n, err := svc.PurgeCaseEmbeddings(ctx, analystA, incA)
	if err != nil || n == 0 {
		t.Fatalf("purge must remove ≥1 embedding: n=%d err=%v", n, err)
	}
	after, _ := svc.RetrieveSimilar(ctx, analystA, "purge-me brute force host", 10)
	for _, c := range after {
		if c.IncidentRef == incA {
			t.Fatal("purged incident's embeddings must not be retrievable")
		}
	}

	// FK cascade path: delete the incident row → its embeddings vanish.
	incB, analystB := ragTestTenant(t, ctx, db, auth.RoleAnalystT1)
	mustIndex(t, ctx, svc, analystB, incB, "tenantB cascade-me brute force host-02", "analyst_t1")
	if err := db.WithTenant(ctx, analystB.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM incidents WHERE id = $1`, incB)
		return e
	}); err != nil {
		t.Fatalf("delete incident: %v", err)
	}
	cascaded, _ := svc.RetrieveSimilar(ctx, analystB, "cascade-me brute force host", 10)
	for _, c := range cascaded {
		if c.IncidentRef == incB {
			t.Fatal("deleting an incident must CASCADE-purge its embeddings (retention: no resurrection)")
		}
	}
}

func mustIndex(t *testing.T, ctx context.Context, svc *ai.Service, p auth.Principal, incidentRef uuid.UUID, chunk, minRole string) {
	t.Helper()
	if err := svc.IndexCase(ctx, p, incidentRef, chunk, minRole); err != nil {
		t.Fatalf("index case: %v", err)
	}
}
