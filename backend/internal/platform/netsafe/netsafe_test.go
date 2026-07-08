package netsafe

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsInternalHost(t *testing.T) {
	internal := []string{"localhost", "foo.local", "svc.internal", "127.0.0.1", "10.0.0.5",
		"192.168.1.1", "169.254.169.254", "::1", "0.0.0.0", "2130706433", "0x7f000001"}
	for _, h := range internal {
		if !IsInternalHost(h) {
			t.Errorf("%q should be classified internal", h)
		}
	}
	public := []string{"hooks.slack.com", "example.com", "8.8.8.8", "1.1.1.1", "api.acme.test"}
	for _, h := range public {
		if IsInternalHost(h) {
			t.Errorf("%q should NOT be classified internal", h)
		}
	}
}

// TestSafeClientBlocksLoopback proves the send-time, post-DNS SSRF guard: the safe client refuses to
// connect to a loopback address even when the URL itself looks like an ordinary request (an httptest
// server binds 127.0.0.1). This is the defence a write-time string check cannot provide.
func TestSafeClientBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	if _, err := SafeClient(2 * time.Second).Get(srv.URL); err == nil {
		t.Fatal("safe client must refuse a connection to a loopback (httptest) address")
	}
}
