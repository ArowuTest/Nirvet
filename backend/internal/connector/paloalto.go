package connector

// §6.11 response — Palo Alto (PAN-OS) network-block client. Blocks an IP by REGISTERING it (User-ID API) with a
// quarantine tag that a customer-pre-created Dynamic Address Group (DAG) matches; the customer's security policy
// denies that DAG. This takes effect WITHOUT a config commit (commit is slow, needs commit-locks, and is disruptive
// on a shared firewall) and is cleanly reversible by UNREGISTERING the tag. Attribution for own-vs-foreign is carried
// by a second per-run correlator tag (PAN-OS registered-IP entries have no free-text comment — tags are the only
// metadata). All calls go through netsafe.SafeClient: a mgmt host that resolves to an RFC-1918 address (an on-prem
// NGFW behind the perimeter) is BLOCKED → the actioner fails loud rather than faking success (that case needs a
// relay, out of this slice). The base URL is the tenant's Panorama/NGFW mgmt host from the encrypted creds bundle.

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
)

// defaultQuarantineTag is the seeded default for the DAG-matched block tag (admin-configurable via creds.PaloAltoTag).
const defaultQuarantineTag = "nirvet-quarantine"

// paloAltoClient calls the PAN-OS XML API (User-ID register/unregister + op show registered-ip).
type paloAltoClient struct {
	base   string // https mgmt host, no trailing slash (Panorama or a cloud-reachable NGFW)
	apiKey string
	tag    string // quarantine tag the customer's DAG + deny rule match
	http   *http.Client
}

// newPaloAltoClient builds the client. Empty base or apiKey is an error (fail closed — never simulate a block). Empty
// tag ⇒ the seeded default. nil http ⇒ SafeClient (SSRF-guarded; blocks internal mgmt hosts → fail loud).
func newPaloAltoClient(base, apiKey, tag string, hc *http.Client) (*paloAltoClient, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return nil, fmt.Errorf("palo alto: no management base URL configured for tenant")
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("palo alto: no API key configured for tenant")
	}
	if strings.TrimSpace(tag) == "" {
		tag = defaultQuarantineTag
	}
	if hc == nil {
		hc = netsafe.SafeClient(30 * time.Second)
	}
	return &paloAltoClient{base: base, apiKey: strings.TrimSpace(apiKey), tag: strings.TrimSpace(tag), http: hc}, nil
}

// panResponse is the PAN-OS XML API envelope. status!="success" ⇒ the API rejected the call → we fail loud.
type panResponse struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Result  struct {
		Count   int `xml:"count"`
		Entries []struct {
			IP   string   `xml:"ip,attr"`
			Tags []string `xml:"tag>member"`
		} `xml:"entry"`
		Msg string `xml:"msg"`
	} `xml:"result"`
	Msg string `xml:"msg"`
}

func (p *panResponse) errMsg() string {
	if s := strings.TrimSpace(p.Result.Msg); s != "" {
		return s
	}
	return strings.TrimSpace(p.Msg)
}

// do POSTs a PAN-OS API call and returns the parsed response, failing loud on transport error (incl. SafeClient's
// ErrBlockedAddress for an unreachable/internal mgmt host), a non-200, or an API status!="success".
func (c *paloAltoClient) do(ctx context.Context, typ, cmd string) (*panResponse, error) {
	form := url.Values{"type": {typ}, "key": {c.apiKey}, "cmd": {cmd}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("palo alto: %w", err) // netsafe ErrBlockedAddress lands here → fail loud (no fake success)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("palo alto: http status %d", resp.StatusCode)
	}
	var pr panResponse
	if err := xml.Unmarshal(body, &pr); err != nil {
		return nil, fmt.Errorf("palo alto: bad response: %w", err)
	}
	if !strings.EqualFold(pr.Status, "success") {
		return nil, fmt.Errorf("palo alto: api error (status %q): %s", pr.Status, pr.errMsg())
	}
	return &pr, nil
}

// register adds the given tags to the registered-IP entry for ip (creates it if absent). Synchronous, no commit.
func (c *paloAltoClient) register(ctx context.Context, ip string, tags []string) error {
	return c.tagOp(ctx, "register", ip, tags)
}

// unregister removes the given tags from ip's registered-IP entry (the entry is auto-dropped when its last tag goes).
func (c *paloAltoClient) unregister(ctx context.Context, ip string, tags []string) error {
	return c.tagOp(ctx, "unregister", ip, tags)
}

func (c *paloAltoClient) tagOp(ctx context.Context, op, ip string, tags []string) error {
	var b strings.Builder
	b.WriteString(`<uid-message><version>1.0</version><type>update</type><payload><`)
	b.WriteString(op)
	b.WriteString(`><entry ip="`)
	b.WriteString(xmlEsc(ip))
	b.WriteString(`"><tag>`)
	for _, t := range tags {
		if strings.TrimSpace(t) == "" {
			continue
		}
		b.WriteString(`<member>`)
		b.WriteString(xmlEsc(t))
		b.WriteString(`</member>`)
	}
	b.WriteString(`</tag></entry></`)
	b.WriteString(op)
	b.WriteString(`></payload></uid-message>`)
	_, err := c.do(ctx, "user-id", b.String())
	return err
}

// registeredTags returns the tags currently on ip's registered-IP entry (found=false if the IP is not registered).
func (c *paloAltoClient) registeredTags(ctx context.Context, ip string) (tags []string, found bool, err error) {
	cmd := `<show><object><registered-ip><ip>` + xmlEsc(ip) + `</ip></registered-ip></object></show>`
	pr, err := c.do(ctx, "op", cmd)
	if err != nil {
		return nil, false, err
	}
	for _, e := range pr.Result.Entries {
		if e.IP == "" || strings.EqualFold(strings.TrimSpace(e.IP), strings.TrimSpace(ip)) {
			return e.Tags, true, nil
		}
	}
	return nil, false, nil
}

// xmlEsc escapes a value for safe insertion into the PAN-OS XML command (both element text and attributes). The IP is
// already validated numeric and tags are Nirvet-controlled, so this is defense-in-depth against a malformed target.
func xmlEsc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// hasTag reports whether tags contains t (case-insensitive, trimmed).
func hasTag(tags []string, t string) bool {
	for _, x := range tags {
		if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(t)) {
			return true
		}
	}
	return false
}

// ipTarget normalizes a block target to a validated IP. Accepts "ip:1.2.3.4", "ipv4:", "ipv6:", "addr:" or a bare IP.
func ipTarget(target string) (string, error) {
	t := strings.TrimSpace(target)
	for _, p := range []string{"ip:", "ipv4:", "ipv6:", "addr:"} {
		if v := strings.TrimPrefix(t, p); v != t {
			t = strings.TrimSpace(v)
			break
		}
	}
	if net.ParseIP(t) == nil {
		return "", fmt.Errorf("palo alto: target %q is not a valid IP address", target)
	}
	return t, nil
}
