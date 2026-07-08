package tenant

import "testing"

// TestValidateEscalationAddress locks the Round-4 L4 SSRF guard: webhook/teams/slack addresses must
// be https and must not target an internal/loopback/link-local/metadata host; email/sms are shape-checked.
func TestValidateEscalationAddress(t *testing.T) {
	cases := []struct {
		channel, address string
		wantErr          bool
	}{
		{"email", "soc@acme.test", false},
		{"email", "not-an-email", true},
		{"email", "a b@x.com", true}, // whitespace
		{"sms", "+15551234567", false},
		{"sms", "123", true},
		{"webhook", "https://hooks.acme.test/x", false},
		{"webhook", "http://hooks.acme.test/x", true},       // not https
		{"webhook", "https://169.254.169.254/latest", true}, // cloud metadata (link-local)
		{"webhook", "https://127.0.0.1/x", true},            // loopback
		{"webhook", "https://10.0.0.5/x", true},             // RFC1918
		{"webhook", "https://192.168.1.1/x", true},          // RFC1918
		{"teams", "https://localhost/x", true},              // localhost
		{"webhook", "https://2130706433/x", true},           // R-5: decimal-integer IP (127.0.0.1)
		{"webhook", "https://0x7f000001/x", true},           // R-5: hex IP encoding
		{"slack", "https://hooks.slack.com/services/x", false},
		{"webhook", "ftp://x", true}, // bad scheme
	}
	for _, c := range cases {
		err := validateEscalationAddress(c.channel, c.address)
		if (err != nil) != c.wantErr {
			t.Errorf("validateEscalationAddress(%q,%q) err=%v wantErr=%v", c.channel, c.address, err, c.wantErr)
		}
	}
}
