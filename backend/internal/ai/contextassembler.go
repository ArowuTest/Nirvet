package ai

// S2b Part 1 — the Investigation Context Assembler. It gathers a BOUNDED, CITED, TENANT-SCOPED evidence package
// for an incident so the copilot grounds on real investigation context instead of 3 fields. Two invariants it must
// never break:
//   - REDACTION (gate non-negotiable #2): the assembled facts are the `evidence` bag into completeExternal — every
//     fact flows through redactLines before egress. Nothing here is concatenated raw into task/question.
//   - TENANT-SCOPING (B4): every reader is called with p.TenantID; the assembler can never read another tenant.
// Citations are ASSEMBLER-PROVIDED: each fact has a stable id (INC/ALERT-n/EVT-n/ENT-n/SOAR-n); the model may cite
// ONLY these ids, and dropInventedCitations hard-strips any id the model invents (an AI cannot cite evidence it was
// not given). First slice = 5 sources: INC + ALERT + EVT + ENT + SOAR-history (MITRE/TI/notebook = second pass).

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

// CitedFact is one assembled evidence line with its stable citation id. Fact is the REDACTABLE text (customer
// telemetry); id is ours (not customer data). Egress prefixes "[id] fact" so the model can cite, and the value
// still redacts (the id prefix is inert).
type CitedFact struct {
	ID   string
	Fact string
}

// SOARReader is the read-only SOAR run-history reader the assembler needs (source 5). It is an INTERFACE injected at
// wiring time, NOT a soar import — so internal/ai never depends on the execution package (the AI-no-direct-execution
// fence stays green). The concrete adapter (over soar.Service) lives in cmd/api, outside internal/ai.
type SOARReader interface {
	RunFactsForIncident(ctx context.Context, tenantID, incidentID uuid.UUID) ([]string, error)
}

// WithSOARReader wires the read-only SOAR history reader. Unset → the assembler simply omits SOAR facts.
func (s *Service) WithSOARReader(r SOARReader) *Service {
	s.soarReader = r
	return s
}

const (
	maxAssembledFacts = 40  // token budget: cap fact count so a huge incident can't blow the prompt (bounded)
	maxAssembledEnt   = 12  // distinct entities cap
	maxCitedFactLen   = 400 // per-fact byte cap (multibyte-safe truncate)
)

// AssembleContext builds the incident's bounded, cited evidence package (all tenant-scoped). Returns the facts in a
// stable order; the caller passes them (id-prefixed) to completeExternal as the redacted evidence bag. A nil/empty
// return is honest "insufficient evidence" — the caller's prompt lets the copilot say so rather than invent.
func (s *Service) AssembleContext(ctx context.Context, p auth.Principal, incidentID uuid.UUID) ([]CitedFact, error) {
	var facts []CitedFact
	add := func(id, f string) {
		if len(facts) >= maxAssembledFacts || strings.TrimSpace(f) == "" {
			return
		}
		if len(f) > maxCitedFactLen {
			f = truncateUTF8(f, maxCitedFactLen) + "…"
		}
		facts = append(facts, CitedFact{ID: id, Fact: f})
	}

	// INC — the incident summary (tenant-scoped Get; a read error is fatal, we don't ground on a guess).
	if s.incidents != nil {
		inc, err := s.incidents.Get(ctx, p.TenantID, incidentID)
		if err != nil {
			return nil, err
		}
		if inc != nil {
			add("INC", "incident_title="+inc.Title)
			add("INC", "severity="+inc.Severity+" stage="+string(inc.Stage))
		}
	}

	// ALERT / EVT / ENT — derived from the incident's alerts (tenant-scoped ListByIncident). Alert read failure is
	// degrade-not-fail: the copilot still answers on the incident summary. Entities are the distinct actor/target
	// refs; the event line is the alert's observable facts.
	if s.alerts != nil {
		alerts, err := s.alerts.ListByIncident(ctx, p.TenantID, incidentID)
		if err == nil {
			seenEnt := map[string]bool{}
			for i, a := range alerts {
				n := i + 1
				add(fmt.Sprintf("ALERT-%d", n), "title="+a.Title+" severity="+a.Severity+" source="+a.Source)
				add(fmt.Sprintf("EVT-%d", n), "event actor="+a.ActorRef+" target="+a.TargetRef+" mitre="+strings.Join(a.MITRE, ","))
				for _, ref := range []string{a.ActorRef, a.TargetRef} {
					if ref != "" && !seenEnt[ref] && len(seenEnt) < maxAssembledEnt {
						seenEnt[ref] = true
						add(fmt.Sprintf("ENT-%d", len(seenEnt)), "entity="+ref)
					}
				}
			}
		}
	}

	// SOAR-n — response actions already taken on this incident (read-only, via the injected reader → no soar import).
	if s.soarReader != nil {
		runs, err := s.soarReader.RunFactsForIncident(ctx, p.TenantID, incidentID)
		if err == nil {
			for i, r := range runs {
				add(fmt.Sprintf("SOAR-%d", i+1), r)
			}
		}
	}

	return facts, nil
}

// evidenceBag renders the assembled facts as the []string evidence bag for completeExternal — each line prefixed
// with its citation id so the model can cite it. The prefix is ours (inert); redactLines still masks the value.
func evidenceBag(facts []CitedFact) []string {
	out := make([]string, 0, len(facts))
	for _, f := range facts {
		out = append(out, "["+f.ID+"] "+f.Fact)
	}
	return out
}

// validCitationIDs is the set of ids the assembler actually provided — the ONLY ids the model may cite.
func validCitationIDs(facts []CitedFact) map[string]bool {
	ids := make(map[string]bool, len(facts))
	for _, f := range facts {
		ids[f.ID] = true
	}
	return ids
}

var citationRe = regexp.MustCompile(`\[([A-Za-z]+-?\d*)\]`)

// dropInventedCitations HARD-STRIPS any [id] in the model's reply that the assembler did not provide (gate §5:
// hard-drop, not flag). An AI cannot surface a citation to evidence it was never given — a hallucinated citation
// would fabricate authority. Valid ids are kept verbatim so the FE can resolve them to the real fact.
func dropInventedCitations(reply string, valid map[string]bool) string {
	if len(valid) == 0 {
		// No evidence assembled → any bracketed citation is invented. But only strip ones that look like our id
		// scheme, to avoid mangling ordinary bracketed prose.
		valid = map[string]bool{}
	}
	return citationRe.ReplaceAllStringFunc(reply, func(m string) string {
		id := strings.Trim(m, "[]")
		if valid[id] {
			return m
		}
		if looksLikeCitationID(id) {
			return "" // invented citation in our scheme — drop it
		}
		return m // ordinary bracketed text, leave alone
	})
}

// looksLikeCitationID reports whether a bracketed token matches the assembler's id scheme (INC or PREFIX-number),
// so dropInventedCitations only strips fabricated CITATIONS, never incidental bracketed prose.
func looksLikeCitationID(id string) bool {
	switch {
	case id == "INC":
		return true
	default:
		for _, pfx := range []string{"ALERT-", "EVT-", "ENT-", "SOAR-", "ASSET-", "MITRE-", "TI-", "NB-", "RAG-"} {
			if strings.HasPrefix(id, pfx) {
				return true
			}
		}
	}
	return false
}
