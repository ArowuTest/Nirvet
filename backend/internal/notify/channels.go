package notify

// Real outbound channels (SRS §6.16 COMM-001): webhook, Teams, Slack — an HTTP POST of the message to
// the recipient URL, over the SSRF-safe client (netsafe) so a rebinding/internal target is refused at
// dial time. Email(SMTP)/SMS are deferred (need per-tenant sender config — slice B).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/netsafe"
)

// webhookChannel delivers a Message by POSTing a JSON body to the recipient URL. One implementation
// backs webhook/teams/slack; `body` shapes the channel-specific payload.
type webhookChannel struct {
	key    string
	client *http.Client
	body   func(m Message) any
}

func (c *webhookChannel) Key() string { return c.key }

func (c *webhookChannel) Send(ctx context.Context, m Message) error {
	// Require https here; the AUTHORITATIVE internal-target block is the safe client's dialer, which
	// rejects a blocked IP AFTER DNS resolution (Round-4 R-5 — a post-DNS check the write-time literal
	// screen in tenant cannot give). Numeric-host encodings simply fail to resolve.
	u, err := url.Parse(m.To)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s recipient must be an https URL", c.key)
	}
	payload, err := json.Marshal(c.body(m))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.To, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req) // returns netsafe.ErrBlockedAddress if the resolved IP is internal
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s webhook returned HTTP %d", c.key, resp.StatusCode)
	}
	return nil
}

// Payload shapes. A generic webhook gets the fields; Slack + Teams get their incoming-webhook formats.
func genericBody(m Message) any {
	return map[string]any{"to": m.To, "subject": m.Subject, "body": m.Body}
}

func slackBody(m Message) any {
	return map[string]any{"text": m.Subject + "\n" + m.Body}
}

func teamsBody(m Message) any {
	return map[string]any{
		"@type": "MessageCard", "@context": "http://schema.org/extensions",
		"summary": m.Subject, "themeColor": "D93F0B", "title": m.Subject, "text": m.Body,
	}
}

// registerHTTPChannels registers webhook/teams/slack, all dialing through the shared SSRF-safe client.
func (s *Service) registerHTTPChannels(client *http.Client) {
	s.register(&webhookChannel{key: "webhook", client: client, body: genericBody})
	s.register(&webhookChannel{key: "slack", client: client, body: slackBody})
	s.register(&webhookChannel{key: "teams", client: client, body: teamsBody})
}

// defaultHTTPClient is the SSRF-safe client used for outbound webhook delivery (10s per request).
func defaultHTTPClient() *http.Client { return netsafe.SafeClient(10 * time.Second) }
