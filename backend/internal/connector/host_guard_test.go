package connector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
	g := NewHostProtectedGuard(fakeHostsReader{patterns: []string{"dc-", "-prod-db"}}, "", "", "", nil)

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
	gErr := NewHostProtectedGuard(fakeHostsReader{err: errors.New("db down")}, "", "", "", nil)
	if _, _, err := gErr.CheckProtected(ctx, tid, string(KindDefender), "isolate_endpoint", "any", nil); err == nil {
		t.Fatal("a config-read error must fail closed (return an error)")
	}
}

// TestHostProtectedGuard_ResolvesCanonicalMachine closes the id-vs-name bypass: a host protected by NAME must
// still be withheld when targeted by `machine:<device-id>`, because the guard now resolves the target to the same
// canonical machine the actioner acts on and matches the protected pattern against its computerDnsName.
func TestHostProtectedGuard_ResolvesCanonicalMachine(t *testing.T) {
	tid := uuid.New()
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"mde-token","expires_in":3600}`)
	})
	// A protected DC (its name matches pattern "dc-") and an ordinary workstation, addressed by device-id.
	mux.HandleFunc("/api/machines/m-dc", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"m-dc","computerDnsName":"SRV-DC-01.corp"}`)
	})
	mux.HandleFunc("/api/machines/m-ws", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"m-ws","computerDnsName":"workstation-9"}`)
	})
	// m-unknown intentionally has no handler → 404 → guard must fail closed.
	srv := httptest.NewServer(mux)
	defer srv.Close()

	g := NewHostProtectedGuard(fakeHostsReader{patterns: []string{"dc-"}}, srv.URL+"/token", srv.URL, "", srv.Client())
	creds, _ := json.Marshal(Credentials{ClientID: "cid", ClientSecret: "secret", AzureTenant: "az"})

	// THE BYPASS, now closed: machine:<id> of a name-protected host resolves to SRV-DC-01.corp → withheld.
	if prot, reason, err := g.CheckProtected(ctx, tid, string(KindDefender), "isolate_endpoint", "machine:m-dc", creds); err != nil || !prot || reason == "" {
		t.Fatalf("machine:<id> of a name-protected host must be withheld: prot=%v reason=%q err=%v", prot, reason, err)
	}
	// A non-protected machine by id → allowed.
	if prot, _, err := g.CheckProtected(ctx, tid, string(KindDefender), "isolate_endpoint", "machine:m-ws", creds); err != nil || prot {
		t.Fatalf("machine:<id> of a non-protected host must be allowed: prot=%v err=%v", prot, err)
	}
	// An unresolvable machine id while crown-jewels exist → fail closed (error → supervisor withholds).
	if _, _, err := g.CheckProtected(ctx, tid, string(KindDefender), "isolate_endpoint", "machine:m-unknown", creds); err == nil {
		t.Fatal("an unresolvable target must fail closed (return an error) when protected hosts are configured")
	}
}
