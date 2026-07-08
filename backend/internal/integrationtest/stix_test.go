package integrationtest

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/ArowuTest/nirvet/internal/threatintel"
	"github.com/google/uuid"
)

// TestIntegration_StixStoreAndEnrichment exercises the §6.10 STIX object store against a real migrated
// Postgres: bundle import, idempotent re-import, STIX-typed enrichment, global-feed visibility, and
// tenant isolation. Gated on NIRVET_TEST_DATABASE_URL like the rest of the suite.
func TestIntegration_StixStoreAndEnrichment(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run integration tests")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	tenSvc := tenant.NewService(tenant.NewRepository(db))
	tnA, err := tenSvc.Create(ctx, tenant.CreateInput{Name: "stix-A-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant A: %v", err)
	}
	tnB, err := tenSvc.Create(ctx, tenant.CreateInput{Name: "stix-B-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant B: %v", err)
	}

	repo := threatintel.NewRepository(db)
	enr := threatintel.NewEnricher(repo)
	svc := threatintel.NewService(repo, enr)

	// Unique indicator value per run so repeated test runs don't collide on matching.
	ip := "203.0.113." + itoa(int(uuid.New().ID()%250)+1)
	indID := "indicator--" + uuid.NewString()
	bundle := json.RawMessage(`{
		"type":"bundle",
		"objects":[
			{"type":"identity","id":"identity--` + uuid.NewString() + `","name":"Acme CTI"},
			{"type":"indicator","id":"` + indID + `","spec_version":"2.1",
			 "pattern":"[ipv4-addr:value = '` + ip + `']","pattern_type":"stix","confidence":88,
			 "labels":["malicious-activity","c2"],
			 "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"command-and-control"}],
			 "object_marking_refs":["marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]},
			{"type":"malware","id":"malware--` + uuid.NewString() + `","name":"BadRat","is_family":false},
			{"type":"totally-not-stix","id":"x--` + uuid.NewString() + `"}
		]
	}`)

	res, err := svc.ImportBundle(ctx, tnA.ID, bundle)
	if err != nil {
		t.Fatalf("import bundle: %v", err)
	}
	if res.Imported != 3 || res.Ignored != 1 {
		t.Fatalf("expected 3 imported / 1 ignored, got %+v", res)
	}

	// Idempotent re-import: same (id, modified) → all skipped, nothing re-applied.
	res2, err := svc.ImportBundle(ctx, tnA.ID, bundle)
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if res2.Imported != 0 || res2.Skipped != 3 {
		t.Fatalf("re-import must be idempotent, got %+v", res2)
	}

	// STIX-typed enrichment for tenant A: an event entity containing the indicator value matches, and
	// the hit carries STIX provenance (object id, confidence, labels, kill-chain).
	matches, err := enr.Enrich(ctx, tnA.ID, []string{"outbound connection to " + ip + ":443"})
	if err != nil {
		t.Fatalf("enrich A: %v", err)
	}
	var stixHit *threatintel.Match
	for i := range matches {
		if matches[i].Source == "stix" && matches[i].ObjectID == indID {
			stixHit = &matches[i]
		}
	}
	if stixHit == nil {
		t.Fatalf("expected a STIX enrichment hit on %s, got %+v", ip, matches)
	}
	if stixHit.Confidence != 88 || stixHit.TLP != "red" || len(stixHit.KillChain) != 1 {
		t.Fatalf("STIX hit lost provenance: %+v", *stixHit)
	}

	// Tenant isolation: B must not see A's indicator...
	if got, _ := repo.GetStix(ctx, tnB.ID, indID); got != nil {
		t.Fatal("tenant B must not see tenant A's STIX object")
	}
	bMatches, err := enr.Enrich(ctx, tnB.ID, []string{"outbound connection to " + ip + ":443"})
	if err != nil {
		t.Fatalf("enrich B: %v", err)
	}
	for _, m := range bMatches {
		if m.ObjectID == indID {
			t.Fatal("tenant B enrichment leaked tenant A's indicator")
		}
	}

	// ...but B DOES see the seeded GLOBAL attack-pattern feed (tenant_id NULL, shared read-only).
	globals, err := svc.ListStix(ctx, tnB.ID, "attack-pattern", 50)
	if err != nil {
		t.Fatalf("list globals for B: %v", err)
	}
	if len(globals) == 0 {
		t.Fatal("tenant B should see the shared global attack-pattern feed")
	}
	for _, g := range globals {
		if g.TenantID != nil {
			t.Fatalf("attack-pattern filter returned a tenant-owned row: %+v", g)
		}
	}

	// Versioned upsert (STIX `modified` rule): same modified → skipped; newer modified → overwrite.
	vID := "indicator--" + uuid.NewString()
	base := time.Now().UTC().Add(-time.Hour)
	v1 := &threatintel.StixObject{ID: vID, Type: "indicator", SpecVersion: "2.1", Created: base,
		Modified: base, Confidence: 50, Pattern: "[domain-name:value = 'v.example']", PatternType: "stix",
		TLP: "amber", Value: "v.example"}
	if applied, err := repo.UpsertStix(ctx, tnA.ID, v1); err != nil || !applied {
		t.Fatalf("v1 insert: applied=%v err=%v", applied, err)
	}
	// Same modified → not applied.
	if applied, err := repo.UpsertStix(ctx, tnA.ID, v1); err != nil || applied {
		t.Fatalf("same-version re-import must skip: applied=%v err=%v", applied, err)
	}
	// Newer modified → applied, and the stored confidence changes.
	v2 := *v1
	v2.Modified = base.Add(time.Minute)
	v2.Confidence = 95
	if applied, err := repo.UpsertStix(ctx, tnA.ID, &v2); err != nil || !applied {
		t.Fatalf("newer-version upsert must apply: applied=%v err=%v", applied, err)
	}
	got, err := repo.GetStix(ctx, tnA.ID, vID)
	if err != nil || got == nil || got.Confidence != 95 {
		t.Fatalf("newer version should have overwritten confidence to 95: %+v err=%v", got, err)
	}

	// R5-H3: two tenants importing the SAME STIX id (as public feeds produce) must each get their own
	// copy — no cross-tenant collision, suppression, or existence oracle.
	sharedID := "indicator--" + uuid.NewString()
	sharedBundle := func(ip string) json.RawMessage {
		return json.RawMessage(`{"type":"bundle","objects":[{"type":"indicator","id":"` + sharedID + `",` +
			`"spec_version":"2.1","pattern":"[ipv4-addr:value = '` + ip + `']","confidence":70}]}`)
	}
	ra, err := svc.ImportBundle(ctx, tnA.ID, sharedBundle("198.51.100.7"))
	if err != nil || ra.Imported != 1 {
		t.Fatalf("tenant A import of shared id: %+v err=%v", ra, err)
	}
	rb, err := svc.ImportBundle(ctx, tnB.ID, sharedBundle("198.51.100.8"))
	if err != nil || rb.Imported != 1 {
		t.Fatalf("tenant B must import the SAME id into its own copy (H3): %+v err=%v", rb, err)
	}
	// Each tenant sees its own copy with its own value.
	ga, _ := repo.GetStix(ctx, tnA.ID, sharedID)
	gb, _ := repo.GetStix(ctx, tnB.ID, sharedID)
	if ga == nil || gb == nil || ga.Value != "198.51.100.7" || gb.Value != "198.51.100.8" {
		t.Fatalf("each tenant must hold its own copy: A=%+v B=%+v", ga, gb)
	}
}

// itoa avoids pulling strconv into the test for a single conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
