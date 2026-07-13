package connector

// Capability-vocabulary guards (external-review: "the capability model should become richer"). The catalogue
// advertises a granular capability set per connector for licensing, UI display and entitlement. For that to be
// trustworthy the vocabulary must be CLOSED (no typo'd token silently ships) and actually EXERCISED (every
// declared capability has a real connector behind it, so the vocabulary isn't aspirational).

import "testing"

// TestAllCapabilitiesAreKnown: every capability advertised by any registry descriptor is a member of the closed
// vocabulary. A typo ("isolate_endpiont") or an ad-hoc string would fail here, keeping the licensing/UI contract
// honest. This is the connector analogue of scripts/check-playbook-actions-cataloged.sh.
func TestAllCapabilitiesAreKnown(t *testing.T) {
	for _, d := range Registry() {
		if len(d.Capabilities) == 0 {
			t.Errorf("connector %q advertises no capabilities — every connector must declare at least one", d.Key)
		}
		for _, c := range d.Capabilities {
			if !KnownCapability(c) {
				t.Errorf("connector %q advertises unknown capability %q — add it to the Capability vocabulary "+
					"deliberately (it drives licensing/UI/entitlement), never as a free string", d.Key, c)
			}
		}
	}
}

// TestCapabilityVocabularyIsExercised: the reverse guard — every capability in the vocabulary is advertised by
// at least one connector. A capability nobody backs is dead vocabulary that would mislead the UI/licensing
// catalogue into offering something the platform can't do. CapAction is the generic fallback and exempt.
func TestCapabilityVocabularyIsExercised(t *testing.T) {
	used := map[Capability]bool{}
	for _, d := range Registry() {
		for _, c := range d.Capabilities {
			used[c] = true
		}
	}
	for c := range knownCapabilities {
		if c == CapAction {
			continue // generic fallback; only used when a descriptor has no finer classification
		}
		if !used[c] {
			t.Errorf("capability %q is in the vocabulary but no connector advertises it — either wire a connector "+
				"that backs it, or drop it so the catalogue only offers real capabilities", c)
		}
	}
}

// TestTicketingConnectorsCataloged: ServiceNow/Jira are a real subsystem (internal/ticketing, SRS §6.16) that
// was missing from the connector catalogue; both must appear with the create_ticket capability so the ITSM
// integration is visible to licensing/UI like every other connector.
func TestTicketingConnectorsCataloged(t *testing.T) {
	want := map[string]bool{"servicenow": false, "jira": false}
	for _, d := range Registry() {
		if _, ok := want[d.Key]; !ok {
			continue
		}
		want[d.Key] = true
		var hasCreateTicket bool
		for _, c := range d.Capabilities {
			if c == CapCreateTicket {
				hasCreateTicket = true
			}
		}
		if !hasCreateTicket {
			t.Errorf("ticketing connector %q must advertise create_ticket, has %v", d.Key, d.Capabilities)
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("expected ticketing connector %q in the catalogue, not found", k)
		}
	}
}
