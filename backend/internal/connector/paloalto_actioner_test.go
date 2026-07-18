package connector

// §6.11 Palo Alto network-block actioner — unit tests against a loopback PAN-OS mock (injected client, no SSRF
// weakening). Proves: contract flags; block registers quarantine + per-run correlator tag; the reverse unregisters
// EXACTLY our ip+correlator (keyed on prior_action_id, not a bare-IP match); a FOREIGN quarantine is attributed
// changed=false so the reverse skips it; and missing creds fail CLOSED (never simulate).

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/soar"
)

// panMock is a minimal PAN-OS XML API: a registered-IP tag store + recorded register/unregister calls.
type panMock struct {
	tags        map[string][]string // ip -> tags currently registered
	lastRegIP   string
	lastRegTags []string
	lastUnIP    string
	lastUnTags  []string
	regCount    int
	unregCount  int
	failStatus  bool // respond status="error" (simulate an API rejection)
}

func newPANServer(t *testing.T, m *panMock) *httptest.Server {
	t.Helper()
	if m.tags == nil {
		m.tags = map[string][]string{}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if m.failStatus {
			fmt.Fprint(w, `<response status="error"><result><msg>bad key</msg></result></response>`)
			return
		}
		cmd := r.Form.Get("cmd")
		switch r.Form.Get("type") {
		case "user-id":
			var uid struct {
				Payload struct {
					Register   *panEntryCmd `xml:"register"`
					Unregister *panEntryCmd `xml:"unregister"`
				} `xml:"payload"`
			}
			if err := xml.Unmarshal([]byte(cmd), &uid); err != nil {
				fmt.Fprint(w, `<response status="error"><result><msg>bad cmd</msg></result></response>`)
				return
			}
			if e := uid.Payload.Register; e != nil {
				m.regCount++
				m.lastRegIP = e.Entry.IP
				m.lastRegTags = e.Entry.Tags
				m.tags[e.Entry.IP] = unionTags(m.tags[e.Entry.IP], e.Entry.Tags)
			}
			if e := uid.Payload.Unregister; e != nil {
				m.unregCount++
				m.lastUnIP = e.Entry.IP
				m.lastUnTags = e.Entry.Tags
				m.tags[e.Entry.IP] = removeTags(m.tags[e.Entry.IP], e.Entry.Tags)
				if len(m.tags[e.Entry.IP]) == 0 {
					delete(m.tags, e.Entry.IP)
				}
			}
			fmt.Fprint(w, `<response status="success"><result><msg>done</msg></result></response>`)
		case "op":
			var show struct {
				IP string `xml:"object>registered-ip>ip"`
			}
			_ = xml.Unmarshal([]byte(cmd), &show)
			ip := strings.TrimSpace(show.IP)
			if tags, ok := m.tags[ip]; ok {
				var b strings.Builder
				for _, tg := range tags {
					b.WriteString("<member>" + tg + "</member>")
				}
				fmt.Fprintf(w, `<response status="success"><result><entry ip="%s"><tag>%s</tag></entry><count>1</count></result></response>`, ip, b.String())
			} else {
				fmt.Fprint(w, `<response status="success"><result><count>0</count></result></response>`)
			}
		default:
			fmt.Fprint(w, `<response status="error"><result><msg>unknown type</msg></result></response>`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

type panEntryCmd struct {
	Entry struct {
		IP   string   `xml:"ip,attr"`
		Tags []string `xml:"tag>member"`
	} `xml:"entry"`
}

func unionTags(cur, add []string) []string {
	out := append([]string{}, cur...)
	for _, t := range add {
		if !hasTag(out, t) {
			out = append(out, t)
		}
	}
	return out
}
func removeTags(cur, rm []string) []string {
	var out []string
	for _, t := range cur {
		if !hasTag(rm, t) {
			out = append(out, t)
		}
	}
	return out
}

func panActionerFor(srv *httptest.Server) *PaloAltoActioner {
	return NewPaloAltoActioner(srv.URL, "apikey", srv.Client())
}

func panFn(t *testing.T, a *PaloAltoActioner, action string) func(context.Context, []byte, string, map[string]any) (string, map[string]any, error) {
	t.Helper()
	for _, ac := range a.Actioners() {
		if ac.Action == action {
			return ac.Fn
		}
	}
	t.Fatalf("action %q not registered", action)
	return nil
}

func TestPaloAlto_ContractFlags(t *testing.T) {
	a := NewPaloAltoActioner("x", "k", nil)
	by := map[string]soar.Actioner{}
	for _, ac := range a.Actioners() {
		by[ac.Action] = ac
	}
	blk, ok := by["block_ip"]
	if !ok || !blk.PreCheck || !blk.Reversible || blk.Inverse != "unblock_ip" || blk.Confirm != nil {
		t.Fatalf("block_ip must be PreCheck+Reversible(Inverse unblock_ip)+Confirm=nil, got %+v", blk)
	}
	unb, ok := by["unblock_ip"]
	if !ok || unb.Inverse != "block_ip" {
		t.Fatalf("unblock_ip must invert block_ip, got %+v", unb)
	}
}

func TestPaloAlto_BlockIP_RegistersWithCorrelatorTag(t *testing.T) {
	m := &panMock{}
	fn := panFn(t, panActionerFor(newPANServer(t, m)), "block_ip")
	creds, _ := json.Marshal(Credentials{}) // empty tag ⇒ default quarantine tag
	params := map[string]any{soar.ActionCorrelatorParam: "run-1:2"}
	ref, prior, err := fn(context.Background(), creds, "ip:198.51.100.7", params)
	if err != nil {
		t.Fatalf("block_ip: %v", err)
	}
	ct := corrTag("run-1:2")
	// The register call must have carried BOTH the quarantine tag and this run's correlator tag.
	if m.regCount != 1 || m.lastRegIP != "198.51.100.7" {
		t.Fatalf("expected one register for the IP, got count=%d ip=%q", m.regCount, m.lastRegIP)
	}
	if !hasTag(m.lastRegTags, defaultQuarantineTag) || !hasTag(m.lastRegTags, ct) {
		t.Fatalf("register must carry [%s, %s], got %v", defaultQuarantineTag, ct, m.lastRegTags)
	}
	if prior["changed"] != true {
		t.Fatalf("fresh block must be changed=true, got %v", prior["changed"])
	}
	wantID := "198.51.100.7|" + ct
	if ref != "198.51.100.7" || prior["action_id"] != wantID {
		t.Fatalf("action_id must encode ip|corrTag %q, got ref=%q action_id=%v", wantID, ref, prior["action_id"])
	}
}

func TestPaloAlto_UnblockIP_UnregistersExactlyOurTag(t *testing.T) {
	// Pre-seed the block as if we created it, then reverse it via prior_action_id and assert the UNREGISTER
	// targeted exactly our ip + correlator tag — not a bare-IP match.
	ct := corrTag("run-9:0")
	m := &panMock{tags: map[string][]string{"203.0.113.9": {defaultQuarantineTag, ct}}}
	fn := panFn(t, panActionerFor(newPANServer(t, m)), "unblock_ip")
	creds, _ := json.Marshal(Credentials{})
	params := map[string]any{"prior_action_id": "203.0.113.9|" + ct}
	_, prior, err := fn(context.Background(), creds, "ip:203.0.113.9", params)
	if err != nil {
		t.Fatalf("unblock_ip: %v", err)
	}
	if m.unregCount != 1 || m.lastUnIP != "203.0.113.9" {
		t.Fatalf("expected one unregister for the IP, got count=%d ip=%q", m.unregCount, m.lastUnIP)
	}
	if !hasTag(m.lastUnTags, defaultQuarantineTag) || !hasTag(m.lastUnTags, ct) {
		t.Fatalf("unregister must remove [%s, %s] (exactly our tags), got %v", defaultQuarantineTag, ct, m.lastUnTags)
	}
	if prior["changed"] != true {
		t.Fatalf("reverse of our block must be changed=true, got %v", prior["changed"])
	}
	if _, stillBlocked := m.tags["203.0.113.9"]; stillBlocked {
		t.Fatal("IP must be fully unregistered after reverse")
	}
}

func TestPaloAlto_ForeignRegistration_NotOursNotRemoved(t *testing.T) {
	// A foreign quarantine (same tag, but WITHOUT our correlator) must be attributed changed=false so the reverse
	// (gated on changed=true) skips it — the REVERSE-COMPOSITION BREAK guard.
	m := &panMock{tags: map[string][]string{"192.0.2.5": {defaultQuarantineTag}}} // foreign: no corr tag
	fn := panFn(t, panActionerFor(newPANServer(t, m)), "block_ip")
	creds, _ := json.Marshal(Credentials{})
	params := map[string]any{soar.ActionCorrelatorParam: "run-2:1"}
	_, prior, err := fn(context.Background(), creds, "ip:192.0.2.5", params)
	if err != nil {
		t.Fatalf("block_ip precheck: %v", err)
	}
	if prior["changed"] != false {
		t.Fatalf("REVERSE-COMPOSITION BREAK: foreign pre-existing block must be changed=false, got %v", prior["changed"])
	}
	if m.regCount != 0 {
		t.Fatalf("foreign pre-existing block must NOT trigger a register, got regCount=%d", m.regCount)
	}
	if _, hasCorr := prior["corr_tag"]; hasCorr {
		t.Fatalf("foreign attribution must not claim a correlator tag, got %v", prior["corr_tag"])
	}
}

func TestPaloAlto_MissingCreds_FailsClosed(t *testing.T) {
	// No base/apiKey configured ⇒ error (fail closed), NOT a simulated success. base/apiKey empty and creds empty.
	a := NewPaloAltoActioner("", "", nil)
	fn := panFn(t, a, "block_ip")
	creds, _ := json.Marshal(Credentials{}) // no PaloAltoBaseURL / PaloAltoAPIKey
	if _, _, err := fn(context.Background(), creds, "ip:198.51.100.1", map[string]any{soar.ActionCorrelatorParam: "r:0"}); err == nil {
		t.Fatal("block_ip with no configured mgmt host/API key must fail closed, got nil error")
	}
}
