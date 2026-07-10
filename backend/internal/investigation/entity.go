package investigation

// §6.9 #124 I-3 — typed entities (INV-003). The existing entity graph works over an opaque `ref` string; this promotes
// it to a typed {kind, value} with a CODE-OWNED kind allow-list (same posture as the field registry: an unknown kind
// is rejected, the vocabulary can't be widened at runtime). A ref is `kind:value`; the value may itself contain colons
// (e.g. an IPv6 address), so only the FIRST colon separates kind from value.

import (
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// entityKinds is the code-owned allow-list of entity kinds (INV-003 enumerates exactly these).
var entityKinds = map[string]bool{
	"user": true, "host": true, "device": true, "ip": true, "domain": true, "file": true,
	"process": true, "email": true, "cloud": true, "vuln": true, "ticket": true, "incident": true,
}

// Entity is a typed investigation entity.
type Entity struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Ref renders the entity back to its canonical `kind:value` ref (the form the alert/correlation stores match on).
func (e Entity) Ref() string { return e.Kind + ":" + e.Value }

// ParseEntity parses and validates a `kind:value` ref. An unknown kind or an empty kind/value is rejected 400.
func ParseEntity(ref string) (Entity, error) {
	i := strings.IndexByte(ref, ':')
	if i <= 0 || i == len(ref)-1 {
		return Entity{}, httpx.ErrBadRequest("entity ref must be kind:value")
	}
	kind, value := ref[:i], ref[i+1:]
	if !entityKinds[kind] {
		return Entity{}, httpx.ErrBadRequest("unknown entity kind: " + kind)
	}
	return Entity{Kind: kind, Value: value}, nil
}
