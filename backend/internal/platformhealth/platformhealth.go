// Package platformhealth exposes an authenticated, aggregated health snapshot of THIS Nirvet instance for the
// operator console (§6.18 platform administration, UI-depth Bucket B / B3). It is deliberately honest about the
// single-sovereign deployment model: it reports the liveness of real dependencies (database, event store) and
// real Go-runtime operational signal, plus the *configured* backend names for services that expose no live ping
// (queue, blobstore, cache). It NEVER fabricates a node fleet, cluster metrics, or a "healthy" status for a
// dependency it cannot actually probe — a truthful "configured" is used instead. It reads no tenant data.
package platformhealth

import (
	"context"
	"runtime"
	"time"
)

// Dependency is one composed dependency's status. Detail carries the backend name where relevant.
type Dependency struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | unavailable | configured | in-memory
	Detail string `json:"detail,omitempty"`
}

// Runtime is real, single-instance Go-process operational signal (no fabrication).
type Runtime struct {
	UptimeSeconds  int64  `json:"uptime_seconds"`
	Goroutines     int    `json:"goroutines"`
	HeapAllocBytes uint64 `json:"heap_alloc_bytes"`
	NumGC          uint32 `json:"num_gc"`
	NumCPU         int    `json:"num_cpu"`
	GoVersion      string `json:"go_version"`
}

// Health is the full snapshot returned to the operator.
type Health struct {
	Status       string       `json:"status"` // ok | degraded
	CheckedAt    time.Time    `json:"checked_at"`
	Instance     string       `json:"instance"` // always "single-sovereign" — explicit, so the UI never implies a fleet
	Dependencies []Dependency `json:"dependencies"`
	Runtime      Runtime      `json:"runtime"`
}

// Pinger is a live liveness probe (database, event store both satisfy it via a method value).
type Pinger func(context.Context) error

// Service composes the snapshot. It holds live probes for the hard dependencies and the configured backend names
// for the soft ones. startedAt is captured once at process start so uptime is real.
type Service struct {
	dbPing       Pinger
	eventPing    Pinger
	eventBackend string
	queueBackend string
	blobBackend  string
	cacheMode    string // "redis" (distributed) or "in-memory" (in-process limiter)
	startedAt    time.Time
	now          func() time.Time // injectable for tests
}

// NewService wires the probes and backend names. cacheRedis=true when a Redis cache/limiter is configured.
func NewService(dbPing, eventPing Pinger, eventBackend, queueBackend, blobBackend string, cacheRedis bool, startedAt time.Time) *Service {
	mode := "in-memory"
	if cacheRedis {
		mode = "redis"
	}
	return &Service{
		dbPing: dbPing, eventPing: eventPing,
		eventBackend: eventBackend, queueBackend: queueBackend, blobBackend: blobBackend,
		cacheMode: mode, startedAt: startedAt, now: time.Now,
	}
}

// Snapshot probes the hard dependencies live and assembles the honest health view. status is "degraded" if any
// hard dependency (database or event store) is unavailable; the soft dependencies never flip the overall status
// because we cannot truthfully assert their liveness here.
func (s *Service) Snapshot(ctx context.Context) Health {
	now := s.now()
	deps := make([]Dependency, 0, 5)
	degraded := false

	if err := s.dbPing(ctx); err != nil {
		deps = append(deps, Dependency{Name: "database", Status: "unavailable"})
		degraded = true
	} else {
		deps = append(deps, Dependency{Name: "database", Status: "ok"})
	}

	if err := s.eventPing(ctx); err != nil {
		deps = append(deps, Dependency{Name: "event_store", Status: "unavailable", Detail: s.eventBackend})
		degraded = true
	} else {
		deps = append(deps, Dependency{Name: "event_store", Status: "ok", Detail: s.eventBackend})
	}

	// Soft dependencies: reported by configured backend name (honest — no live ping surfaced), never faked "ok".
	deps = append(deps, Dependency{Name: "queue", Status: "configured", Detail: s.queueBackend})
	deps = append(deps, Dependency{Name: "blobstore", Status: "configured", Detail: s.blobBackend})
	deps = append(deps, Dependency{Name: "cache", Status: s.cacheMode})

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	status := "ok"
	if degraded {
		status = "degraded"
	}
	return Health{
		Status:       status,
		CheckedAt:    now,
		Instance:     "single-sovereign",
		Dependencies: deps,
		Runtime: Runtime{
			UptimeSeconds:  int64(now.Sub(s.startedAt).Seconds()),
			Goroutines:     runtime.NumGoroutine(),
			HeapAllocBytes: m.HeapAlloc,
			NumGC:          m.NumGC,
			NumCPU:         runtime.NumCPU(),
			GoVersion:      runtime.Version(),
		},
	}
}
