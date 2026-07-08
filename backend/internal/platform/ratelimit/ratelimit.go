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

// ByIP keys on the client IP (honours X-Forwarded-For behind a proxy).
func ByIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
