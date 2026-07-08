package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBurstThenDeny: with no refill and burst N, the first N calls pass then deny.
func TestBurstThenDeny(t *testing.T) {
	l := New(0, 3) // 0/sec refill, burst 3
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("call %d should be allowed within burst", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("call beyond burst must be denied")
	}
}

// TestPerKeyIsolation: buckets are independent per key.
func TestPerKeyIsolation(t *testing.T) {
	l := New(0, 1)
	if !l.Allow("a") || l.Allow("a") {
		t.Fatal("key a: first allowed, second denied")
	}
	if !l.Allow("b") {
		t.Fatal("key b has its own bucket and should be allowed")
	}
}

// TestClientIPSpoofResistance: an attacker who sets a random left-most
// X-Forwarded-For must NOT get a fresh limit key. With one trusted proxy we take the
// right-most entry (added by our LB), so the spoofed prefix is ignored.
func TestClientIPSpoofResistance(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "10.0.0.9:5555" // the LB (immediate peer)
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.7")

	// Depth 1 (single trusted LB): the real client is the right-most entry.
	if got := clientIP(r, 1); got != "203.0.113.7" {
		t.Fatalf("depth 1 = %q, want the right-most (real) client 203.0.113.7", got)
	}
	// The spoofed left-most value must never be chosen at depth 1.
	if clientIP(r, 1) == "6.6.6.6" {
		t.Fatal("spoofed left-most X-Forwarded-For must not become the limit key")
	}
	// Attacker floods with varied spoofed prefixes: the key stays stable.
	r2 := httptest.NewRequest(http.MethodPost, "/", nil)
	r2.RemoteAddr = "10.0.0.9:5555"
	r2.Header.Set("X-Forwarded-For", "9.9.9.9, 203.0.113.7")
	if clientIP(r, 1) != clientIP(r2, 1) {
		t.Fatal("varying the spoofed prefix must not change the derived client IP")
	}
	// No X-Forwarded-For: fall back to the TCP peer.
	r3 := httptest.NewRequest(http.MethodPost, "/", nil)
	r3.RemoteAddr = "198.51.100.4:1234"
	if got := clientIP(r3, 1); got != "198.51.100.4" {
		t.Fatalf("no XFF = %q, want RemoteAddr host 198.51.100.4", got)
	}
}

// TestMiddleware429: the middleware returns 429 once the bucket is empty.
func TestMiddleware429(t *testing.T) {
	l := New(0, 1)
	mw := Middleware(l, func(r *http.Request) string { return "fixed" })
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first = %d, want 200", first.Code)
	}
	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second = %d, want 429", second.Code)
	}
}
