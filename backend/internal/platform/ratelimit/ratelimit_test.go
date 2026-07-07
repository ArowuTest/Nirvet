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
