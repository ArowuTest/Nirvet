package tenant

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// The resolvers treat an entry as a cache hit only while time.Now().Before(expires); invalidate
// must drop both policy caches for a tenant so a config change is visible at once on this instance.
func TestPolicyCacheInvalidateDropsBoth(t *testing.T) {
	c := newPolicyCache(time.Minute)
	id := uuid.New()
	c.mu.Lock()
	c.corr[id] = corrCacheEntry{window: time.Hour, promoteThreshold: 70, minAlerts: 2, expires: time.Now().Add(time.Minute)}
	c.sla[id] = slaCacheEntry{bySeverity: map[string][2]time.Duration{"critical": {time.Minute, time.Hour}}, expires: time.Now().Add(time.Minute)}
	c.mu.Unlock()

	c.invalidate(id)

	c.mu.Lock()
	_, corrOK := c.corr[id]
	_, slaOK := c.sla[id]
	c.mu.Unlock()
	if corrOK || slaOK {
		t.Fatalf("invalidate must drop both caches (corr=%v sla=%v)", corrOK, slaOK)
	}
}

func TestPolicyCacheTTLSemantics(t *testing.T) {
	c := newPolicyCache(time.Minute)
	id := uuid.New()
	// A fresh entry is live (a hit); a past-dated entry is stale (a miss) under the same predicate
	// the resolvers use.
	c.corr[id] = corrCacheEntry{expires: time.Now().Add(c.ttl)}
	if !time.Now().Before(c.corr[id].expires) {
		t.Fatal("fresh entry should be a cache hit")
	}
	c.corr[id] = corrCacheEntry{expires: time.Now().Add(-time.Second)}
	if time.Now().Before(c.corr[id].expires) {
		t.Fatal("expired entry should be a cache miss")
	}
}
