package investigation

// §6.9 #124 I-3 — pure unit tests for typed-entity parsing (the code-owned kind allow-list).

import "testing"

func TestParseEntity(t *testing.T) {
	ok := []struct{ ref, kind, value string }{
		{"host:FIN-01", "host", "FIN-01"},
		{"user:jane@acme.com", "user", "jane@acme.com"},
		{"ip:2001:db8::1", "ip", "2001:db8::1"}, // value keeps its colons (split on the first only)
	}
	for _, c := range ok {
		e, err := ParseEntity(c.ref)
		if err != nil {
			t.Fatalf("%q should parse: %v", c.ref, err)
		}
		if e.Kind != c.kind || e.Value != c.value {
			t.Fatalf("%q → %+v, want {%s %s}", c.ref, e, c.kind, c.value)
		}
		if e.Ref() != c.ref {
			t.Fatalf("round-trip Ref() = %q, want %q", e.Ref(), c.ref)
		}
	}
	bad := []string{"secret:x", "hostFIN", "host:", ":value", "", "unknownkind:v"}
	for _, ref := range bad {
		if _, err := ParseEntity(ref); err == nil {
			t.Fatalf("%q must be rejected (bad kind / malformed)", ref)
		}
	}
}
