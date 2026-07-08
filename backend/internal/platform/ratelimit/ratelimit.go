// Package ratelimit provides token-bucket rate limiting keyed by an arbitrary
// string (client IP for login brute-force protection, principal id for general API
// limits). Two backends satisfy the Allower interface: an in-memory limiter
// (per-instance, the default) and a Redis limiter (global across API replicas —
// select it once the API scales horizontally; see ADR-0005 / ARCHITECTURE_GATES).
package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"golang.org/x/time/rate"
)

// Allower reports whether a key may proceed now. Implemented by the in-memory
// Limiter and the RedisLimiter — the middleware depends only on this.
type Allower interface {
	Allow(key string) bool
}

// Limiter holds a token bucket per key with idle eviction.
type Limiter struct {
	r   rate.Limit
	b   int
	mu  sync.Mutex
	m   map[string]*entry
	ttl time.Duration
}

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

// New builds a limiter allowing r requests/second with burst b.
func New(perSecond float64, burst int) *Limiter {
	l := &Limiter{r: rate.Limit(perSecond), b: burst, m: map[string]*entry{}, ttl: 10 * time.Minute}
	go l.sweep()
	return l
}

// Allow reports whether the key may proceed now.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	e, ok := l.m[key]
	if !ok {
		e = &entry{lim: rate.NewLimiter(l.r, l.b)}
		l.m[key] = e
	}
	e.seen = time.Now()
	l.mu.Unlock()
	return e.lim.Allow()
}

func (l *Limiter) sweep() {
	t := time.NewTicker(l.ttl)
	defer t.Stop()
	for range t.C {
		cut := time.Now().Add(-l.ttl)
		l.mu.Lock()
		for k, e := range l.m {
			if e.seen.Before(cut) {
				delete(l.m, k)
			}
		}
		l.mu.Unlock()
	}
}

// KeyFunc derives the limit key from a request.
type KeyFunc func(*http.Request) string

// defaultTrustedProxies is the number of upstream proxies whose X-Forwarded-For
// entries we trust by default (the platform load balancer). Deployments behind a
// deeper chain (CDN -> LB) should use ByIPTrusting with the real depth.
const defaultTrustedProxies = 1

// clientIP returns the client address, trusting ONLY the rightmost trustedProxies
// entries of X-Forwarded-For — those are appended by infrastructure we control. The
// leftmost entries are client-supplied and spoofable; taking them (as the old code
// did) let an attacker mint a fresh rate-limit bucket per request by setting a random
// X-Forwarded-For, defeating per-IP login throttling. We take the entry trustedProxies
// from the right (the hop just before our outermost trusted proxy).
func clientIP(r *http.Request, trustedProxies int) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && trustedProxies > 0 {
		parts := strings.Split(xff, ",")
		idx := len(parts) - trustedProxies
		if idx < 0 {
			idx = 0
		}
		if ip := strings.TrimSpace(parts[idx]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ByIP keys on the client IP, trusting a single upstream proxy (the platform LB).
func ByIP(r *http.Request) string { return clientIP(r, defaultTrustedProxies) }

// ByIPTrusting returns a KeyFunc that trusts trustedProxies upstream hops when parsing
// X-Forwarded-For. Use when the deployment sits behind a known proxy depth > 1.
func ByIPTrusting(trustedProxies int) KeyFunc {
	return func(r *http.Request) string { return clientIP(r, trustedProxies) }
}

// ByPrincipal keys on the authenticated user id, falling back to IP.
func ByPrincipal(r *http.Request) string {
	if p, ok := auth.PrincipalFrom(r.Context()); ok {
		return "u:" + p.UserID.String()
	}
	return "ip:" + ByIP(r)
}

// Middleware returns a 429 when the key exceeds its bucket.
func Middleware(l Allower, key KeyFunc) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.Allow(key(r)) {
				httpx.Error(w, httpx.ErrTooManyRequests("rate limit exceeded"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
