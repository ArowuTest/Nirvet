package ratelimit_test

// Redis-backed rate limiter, gated on NIRVET_REDIS_ADDR. Proves the property that
// matters for horizontal scale: two independent limiter instances (simulating two
// API replicas) share one global bucket.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/ratelimit"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func dialRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("NIRVET_REDIS_ADDR")
	if addr == "" {
		t.Skip("set NIRVET_REDIS_ADDR to run Redis rate-limit tests")
	}
	rc := redis.NewClient(&redis.Options{Addr: addr})
	if err := rc.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("redis ping: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })
	return rc
}

func TestRedisLimiter_BurstThenDeny(t *testing.T) {
	rc := dialRedis(t)
	key := uuid.NewString()
	l := ratelimit.NewRedis(rc, 0.01, 3, "test") // negligible refill, burst 3
	allowed := 0
	for i := 0; i < 5; i++ {
		if l.Allow(key) {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("expected exactly 3 allowed (burst), got %d", allowed)
	}
}

// The distributed property: a SECOND limiter instance sees the same depleted bucket.
func TestRedisLimiter_SharedAcrossInstances(t *testing.T) {
	rc := dialRedis(t)
	key := uuid.NewString()
	replicaA := ratelimit.NewRedis(rc, 0.01, 2, "test")
	replicaB := ratelimit.NewRedis(rc, 0.01, 2, "test")

	if !replicaA.Allow(key) || !replicaA.Allow(key) {
		t.Fatal("replica A should allow the 2-token burst")
	}
	// Replica B, hitting the SAME global bucket, must now be limited.
	if replicaB.Allow(key) {
		t.Fatal("replica B must be limited — the bucket is shared across instances")
	}
}

func TestRedisLimiter_Refills(t *testing.T) {
	rc := dialRedis(t)
	key := uuid.NewString()
	l := ratelimit.NewRedis(rc, 100, 1, "test") // 100 tokens/sec, burst 1
	if !l.Allow(key) {
		t.Fatal("first request should be allowed")
	}
	if l.Allow(key) {
		t.Fatal("immediate second request should be limited")
	}
	time.Sleep(30 * time.Millisecond) // ~3 tokens accrue (capped at burst 1)
	if !l.Allow(key) {
		t.Fatal("request after refill window should be allowed")
	}
}
