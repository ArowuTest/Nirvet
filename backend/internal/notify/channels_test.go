package notify

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWebhookChannelDelivers proves the webhook channel POSTs the expected JSON body to the recipient
// URL. It uses a TLS httptest server + that server's own client (which trusts its cert and reaches
// loopback) — the production SSRF-safe dialer's loopback block is covered by netsafe's own test, and
// the channel takes an injected client precisely so this path is testable.
func TestWebhookChannelDelivers(t *testing.T) {
	var gotBody map[string]any
	var gotCT string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Test-only client that trusts the httptest self-signed cert; production uses netsafe.SafeClient.
	testClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test server
	ch := &webhookChannel{key: "webhook", client: testClient, body: genericBody}
	if err := ch.Send(context.Background(), Message{To: srv.URL, Subject: "S", Body: "B"}); err != nil {
		t.Fatalf("webhook delivery failed: %v", err)
	}
	if gotCT != "application/json" {
		t.Fatalf("expected application/json, got %q", gotCT)
	}
	if gotBody["subject"] != "S" || gotBody["body"] != "B" {
		t.Fatalf("unexpected body: %+v", gotBody)
	}
}

// TestWebhookRejectsNonHTTPS locks the scheme guard.
func TestWebhookRejectsNonHTTPS(t *testing.T) {
	ch := &webhookChannel{key: "webhook", client: http.DefaultClient, body: genericBody}
	if err := ch.Send(context.Background(), Message{To: "http://hooks.acme.test/x", Subject: "S"}); err == nil {
		t.Fatal("a non-https recipient must be rejected")
	}
	if err := ch.Send(context.Background(), Message{To: "://bad", Subject: "S"}); err == nil {
		t.Fatal("a malformed recipient must be rejected")
	}
}

// TestChannelPayloadShapes locks the Slack/Teams incoming-webhook formats.
func TestChannelPayloadShapes(t *testing.T) {
	m := Message{Subject: "Alert", Body: "details"}
	if slackBody(m).(map[string]any)["text"] != "Alert\ndetails" {
		t.Fatal("slack payload must be a single text field")
	}
	teams := teamsBody(m).(map[string]any)
	if teams["@type"] != "MessageCard" || teams["title"] != "Alert" || teams["text"] != "details" {
		t.Fatalf("teams payload must be a MessageCard: %+v", teams)
	}
}
