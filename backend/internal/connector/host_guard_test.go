package connector

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

type fakeHostsReader struct {
	patterns []string
	err      error
}

func (f fakeHostsReader) ProtectedHosts(_ context.Context, _ uuid.UUID) ([]string, error) {
	return f.patterns, f.err
}

func TestHostProtectedGuard(t *testing.T) {
	tid := uuid.New()
	ctx := context.Background()
	g := NewHostProtectedGuard(fakeHostsReader{patterns: []string{"dc-", "-prod-db"}})

	// Vendor-aware no-ops: non-Defender connector, and the reversible release action.
	if prot, _, err := g.CheckProtected(ctx, tid, string(KindEntraID), "disable_user", "dc-01", nil); err != nil || prot {
		t.Fatal("guard must no-op for a non-Defender connector")
	}
	if prot, _, err := g.CheckProtected(ctx, tid, string(KindDefender), "release_endpoint", "dc-01", nil); err != nil || prot {
		t.Fatal("guard must no-op for the reversible release_endpoint action")
	}

	// Defender isolate of a crown-jewel host (case-insensitive substring) → withheld.
	if prot, reason, err := g.CheckProtected(ctx, tid, string(KindDefender), "isolate_endpoint", "SRV-DC-01.corp", nil); err != nil || !prot || reason == "" {
		t.Fatalf("isolate of a protected host must be withheld: prot=%v reason=%q err=%v", prot, reason, err)
	}
	// Defender isolate of a non-protected host → allowed.
	if prot, _, err := g.CheckProtected(ctx, tid, string(KindDefender), "isolate_endpoint", "workstation-42", nil); err != nil || prot {
		t.Fatal("isolate of a non-protected host must be allowed")
	}
	// H-1: a MIS-CASED connector/action key must NOT slip past the guard (the actioner matches it
	// case-insensitively, so the guard must too — else a "Defender" override isolates a protected host).
	if prot, _, err := g.CheckProtected(ctx, tid, "Defender", "Isolate_Endpoint", "SRV-DC-01.corp", nil); err != nil || !prot {
		t.Fatalf("mis-cased Defender/isolate of a protected host must still be withheld: prot=%v err=%v", prot, err)
	}

	// A config-read error fails CLOSED (returns the error → the supervisor withholds).
	gErr := NewHostProtectedGuard(fakeHostsReader{err: errors.New("db down")})
	if _, _, err := gErr.CheckProtected(ctx, tid, string(KindDefender), "isolate_endpoint", "any", nil); err == nil {
		t.Fatal("a config-read error must fail closed (return an error)")
	}
}
