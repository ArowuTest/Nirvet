package ratelimit

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// tokenBucket is an atomic token-bucket refill in Lua so limits are correct across
// concurrent API replicas (the whole point of the Redis backend). It refills at
// `rate` tokens/sec up to `burst`, spends one token per allowed request, and sets a
// TTL so idle keys expire. Returns 1 (allowed) or 0 (limited).
var tokenBucket = redis.NewScript(`
local rate    = tonumber(ARGV[1])
local burst   = tonumber(ARGV[2])
local now     = tonumber(ARGV[3])
local reqd    = tonumber(ARGV[4])
local data    = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens  = tonumber(data[1])
local ts      = tonumber(data[2])
if tokens == nil then tokens = burst; ts = now end
local delta = now - ts
if delta < 0 then delta = 0 end
tokens = math.min(burst, tokens + delta * rate)
local allowed = 0
if tokens >= reqd then tokens = tokens - reqd; allowed = 1 end
redis.call('HMSET', KEYS[1], 'tokens', tokens, 'ts', now)
local ttl = math.ceil(burst / rate) + 10
redis.call('EXPIRE', KEYS[1], ttl)
return allowed
`)

// Build selects the limiter backend: Redis when a client is provided (global,
// multi-instance), otherwise the in-memory limiter (per-instance default).
func Build(rc *redis.Client, perSecond float64, burst int, namespace string) Allower {
	if rc != nil {
		return NewRedis(rc, perSecond, burst, namespace)
	}
	return New(perSecond, burst)
}

// RedisLimiter is a token-bucket limiter backed by Redis, shared across instances.
type RedisLimiter struct {
	rc     *redis.Client
	rate   float64
	burst  int
	prefix string
}

// NewRedis builds a Redis-backed limiter. namespace keeps each logical limiter
// (login / api / webhook) in its own key space so they don't collide.
func NewRedis(rc *redis.Client, perSecond float64, burst int, namespace string) *RedisLimiter {
	return &RedisLimiter{rc: rc, rate: perSecond, burst: burst, prefix: "rl:" + namespace + ":"}
}

// Allow reports whether the key may proceed now. It fails OPEN on a Redis error
// (availability over strictness): a rate limiter must never take the API down. The
// in-memory limiter remains the default; Redis is opt-in for horizontal scale.
func (l *RedisLimiter) Allow(key string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	now := float64(time.Now().UnixNano()) / 1e9
	res, err := tokenBucket.Run(ctx, l.rc, []string{l.prefix + key}, l.rate, l.burst, now, 1).Int()
	if err != nil {
		return true // fail open
	}
	return res == 1
}
