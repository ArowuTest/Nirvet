package platformhealth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func okPing(context.Context) error  { return nil }
func badPing(context.Context) error { return errors.New("down") }

func TestSnapshot_AllHealthy(t *testing.T) {
	start := time.Now().Add(-90 * time.Second)
	s := NewService(okPing, okPing, "clickhouse", "nats", "gcs", true, start)
	h := s.Snapshot(context.Background())

	if h.Status != "ok" {
		t.Fatalf("status = %q, want ok", h.Status)
	}
	if h.Instance != "single-sovereign" {
		t.Fatalf("instance = %q, want single-sovereign", h.Instance)
	}
	byName := map[string]Dependency{}
	for _, d := range h.Dependencies {
		byName[d.Name] = d
	}
	if byName["database"].Status != "ok" || byName["event_store"].Status != "ok" {
		t.Fatalf("hard deps not ok: %+v", byName)
	}
	if byName["event_store"].Detail != "clickhouse" {
		t.Fatalf("event_store detail = %q", byName["event_store"].Detail)
	}
	// Soft deps report configured backend names, never a fabricated "ok".
	if byName["queue"].Status != "configured" || byName["queue"].Detail != "nats" {
		t.Fatalf("queue dep wrong: %+v", byName["queue"])
	}
	if byName["cache"].Status != "redis" {
		t.Fatalf("cache mode = %q, want redis", byName["cache"].Status)
	}
	if h.Runtime.Goroutines < 1 || h.Runtime.NumCPU < 1 || h.Runtime.GoVersion == "" {
		t.Fatalf("runtime block not populated: %+v", h.Runtime)
	}
	if h.Runtime.UptimeSeconds < 80 {
		t.Fatalf("uptime = %d, want >= 80", h.Runtime.UptimeSeconds)
	}
}

func TestSnapshot_DegradedWhenHardDepDown(t *testing.T) {
	s := NewService(badPing, okPing, "postgres", "postgres", "local", false, time.Now())
	h := s.Snapshot(context.Background())
	if h.Status != "degraded" {
		t.Fatalf("status = %q, want degraded", h.Status)
	}
	var db Dependency
	for _, d := range h.Dependencies {
		if d.Name == "database" {
			db = d
		}
	}
	if db.Status != "unavailable" {
		t.Fatalf("database status = %q, want unavailable", db.Status)
	}
	// cache falls back to in-memory when Redis isn't configured.
	for _, d := range h.Dependencies {
		if d.Name == "cache" && d.Status != "in-memory" {
			t.Fatalf("cache mode = %q, want in-memory", d.Status)
		}
	}
}
