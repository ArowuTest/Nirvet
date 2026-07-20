package ai

// S2b Part 1 tests — the assembler invariants (gate §2 + close-out bar), all DB-free:
//   - a PII identifier inside an ASSEMBLED fact egresses MASKED (non-negotiable #2: assembler output rides the
//     redacted evidence bag), mutation-sensitive;
//   - invented citations are HARD-DROPPED, real ones kept, ordinary bracketed prose untouched (citation integrity);
//   - AssembleContext passes p.TenantID to every reader (B4 tenant-scoping — never reads cross-tenant).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

// Non-negotiable #2: an assembled fact carrying a customer identifier egresses MASKED — because the assembler
// output is the `evidence` bag through completeExternal, which redacts. Mutation: appending the bag to task/question
// raw (bypassing redaction) → the identifier would appear → this asserts it does NOT.
func TestAssembledFact_PIIMaskedAtEgress(t *testing.T) {
	facts := []CitedFact{
		{ID: "INC", Fact: "incident_title=lateral movement"},
		{ID: "ENT-1", Fact: "entity=admin@corp.example"},
		{ID: "EVT-1", Fact: "event actor=10.1.2.3 target=host-db-01"},
	}
	s := &Service{} // nil redaction → balanced floor
	cap := &captureProvider{}
	_, _, err := s.completeExternal(context.Background(), uuid.New(), cap, egress{task: copilotTask, evidence: evidenceBag(facts)})
	if err != nil {
		t.Fatalf("completeExternal: %v", err)
	}
	for _, raw := range []string{"admin@corp.example", "10.1.2.3"} {
		if strings.Contains(cap.user, raw) {
			t.Fatalf("assembled-fact PII %q egressed unmasked:\n%s", raw, cap.user)
		}
	}
	// The citation ids (ours, not customer data) DO survive so the model can cite them.
	if !strings.Contains(cap.user, "[INC]") || !strings.Contains(cap.user, "[ENT-1]") {
		t.Fatalf("citation ids must survive redaction so the model can cite:\n%s", cap.user)
	}
}

// Reviewer close-out (copilot-P0 C2, broadened by the richer assembler): the assembler egresses MORE customer
// telemetry (entity/actor/hostname/title), and balanced mode's tokenMask only masks PATTERN hits — so a non-pattern
// identifier (a plain hostname/name) survives balanced (the documented residual). STRICT mode (gov default,
// register D2) wholesale-masks it. This proves the mitigation and documents the residual honestly.
func TestAssembledFact_NonPatternMaskedUnderStrict(t *testing.T) {
	facts := []CitedFact{{ID: "EVT-1", Fact: "event actor=jsmith target=host-db-01 mitre=T1078"}}
	bag := evidenceBag(facts)

	// Balanced (the default): the non-pattern hostname + name survive — the documented balanced residual.
	bal, _ := redactLines(bag, RedactionPolicy{Enabled: true, Mode: RedactBalanced}, floor())
	if !strings.Contains(bal[0], "host-db-01") || !strings.Contains(bal[0], "jsmith") {
		t.Fatalf("precondition: balanced should leave the non-pattern identifiers (documented residual): %q", bal[0])
	}

	// Strict: the free-text value wholesale-masks → no cleartext identifier egresses.
	strict, _ := redactLines(bag, RedactionPolicy{Enabled: true, Mode: RedactStrict}, floor())
	for _, raw := range []string{"host-db-01", "jsmith"} {
		if strings.Contains(strict[0], raw) {
			t.Fatalf("strict must wholesale-mask the non-pattern identifier %q: %q", raw, strict[0])
		}
	}
	if !strings.Contains(strict[0], "TEXT_") {
		t.Fatalf("strict must produce a TEXT_ wholesale mask: %q", strict[0])
	}
	// The citation id survives redaction in BOTH modes so the model can still cite the evidence.
	if !strings.Contains(strict[0], "[EVT-1]") {
		t.Fatalf("citation id must survive strict redaction so the model can cite: %q", strict[0])
	}
}

func TestDropInventedCitations(t *testing.T) {
	valid := validCitationIDs([]CitedFact{{ID: "INC"}, {ID: "ALERT-1"}, {ID: "ENT-2"}})
	got := dropInventedCitations(
		"Per [INC] and [ALERT-1] the host [ENT-2] is compromised; also see [ALERT-9] and [SOAR-3] (see the note [reminder]).",
		valid,
	)
	// Real ids kept.
	for _, keep := range []string{"[INC]", "[ALERT-1]", "[ENT-2]"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("real citation %q must be kept: %q", keep, got)
		}
	}
	// Invented ids in our scheme hard-dropped.
	for _, drop := range []string{"[ALERT-9]", "[SOAR-3]"} {
		if strings.Contains(got, drop) {
			t.Fatalf("invented citation %q must be dropped: %q", drop, got)
		}
	}
	// Ordinary bracketed prose left alone.
	if !strings.Contains(got, "[reminder]") {
		t.Fatalf("ordinary bracketed prose must be preserved: %q", got)
	}
}

// fakeIncidentReader asserts every read is scoped to the expected tenant — proving AssembleContext never reads
// another tenant's incident.
type fakeIncidentReader struct {
	t          *testing.T
	wantTenant uuid.UUID
}

func (f fakeIncidentReader) Get(_ context.Context, tenantID, id uuid.UUID) (*incident.Incident, error) {
	if tenantID != f.wantTenant {
		f.t.Fatalf("incident read crossed tenants: got %s want %s", tenantID, f.wantTenant)
	}
	return &incident.Incident{ID: id, Title: "t", Severity: "high", Stage: "triage"}, nil
}

type fakeSOARReader struct {
	t          *testing.T
	wantTenant uuid.UUID
}

func (f fakeSOARReader) RunFactsForIncident(_ context.Context, tenantID, _ uuid.UUID) ([]string, error) {
	if tenantID != f.wantTenant {
		f.t.Fatalf("SOAR read crossed tenants: got %s want %s", tenantID, f.wantTenant)
	}
	return []string{"action=isolate_host status=succeeded"}, nil
}

func TestAssembleContext_TenantScoped(t *testing.T) {
	tid := uuid.New()
	s := &Service{
		incidents:  fakeIncidentReader{t: t, wantTenant: tid},
		soarReader: fakeSOARReader{t: t, wantTenant: tid},
		// alerts left nil → the ALERT/EVT/ENT block is skipped (no DB needed for this scoping test).
	}
	p := auth.Principal{UserID: uuid.New(), TenantID: tid}
	facts, err := s.AssembleContext(context.Background(), p, uuid.New())
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	// Both readers were called with the caller's tenant (asserted inside the fakes) and produced cited facts.
	var haveINC, haveSOAR bool
	for _, f := range facts {
		if f.ID == "INC" {
			haveINC = true
		}
		if strings.HasPrefix(f.ID, "SOAR-") {
			haveSOAR = true
		}
	}
	if !haveINC || !haveSOAR {
		t.Fatalf("expected INC + SOAR facts, got %+v", facts)
	}
}

// A read error on the incident is fatal (we don't ground on a guess), never a silent empty context.
func TestAssembleContext_IncidentReadErrorPropagates(t *testing.T) {
	s := &Service{incidents: errIncidentReader{}}
	if _, err := s.AssembleContext(context.Background(), auth.Principal{TenantID: uuid.New()}, uuid.New()); err == nil {
		t.Fatal("an incident read error must propagate, not yield a silent empty context")
	}
}

type errIncidentReader struct{}

func (errIncidentReader) Get(context.Context, uuid.UUID, uuid.UUID) (*incident.Incident, error) {
	return nil, errors.New("boom")
}
