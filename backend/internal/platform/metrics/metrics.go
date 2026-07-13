// Package metrics exposes Prometheus metrics for the platform (NFR-007
// observability). It records HTTP request counts/latency by route template (low
// cardinality) and platform counters, and serves /metrics.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nirvet_http_requests_total",
		Help: "HTTP requests by method, route template and status.",
	}, []string{"method", "route", "status"})

	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "nirvet_http_request_duration_seconds",
		Help:    "HTTP request latency by method and route template.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})

	// EventsIngested counts accepted raw events (incremented by ingestion).
	EventsIngested = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nirvet_events_ingested_total",
		Help: "Raw security events accepted for ingestion.",
	})

	// AlertsRaised counts alerts created by detection.
	AlertsRaised = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nirvet_alerts_raised_total",
		Help: "Alerts raised by the detection engine.",
	})

	// SyslogDropped counts syslog lines dropped because ingestion failed (a backend blip). A syslog TCP
	// source never retries a line already read off the socket, so this is the silent-loss signal for the
	// operator's syslog connector — a rising rate should page (M6).
	SyslogDropped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nirvet_syslog_dropped_total",
		Help: "Syslog lines dropped due to an ingestion failure.",
	})

	// --- Retention reconciliation (external-audit Finding 1) ---
	// Retention deletes the payload blob before its metadata row (compliance-safe, never DB-first). Blob
	// storage and Postgres can't share a transaction, so a crash between the two steps transiently leaves a
	// row whose blob is already gone; the next sweep heals it (idempotent blob delete). These give operators
	// evidence that the temporary inconsistency is actually healing.

	// RetentionMetadataCleanupFailures counts raw_events rows whose payload blob was deleted but whose
	// metadata-row delete then failed — i.e. rows that became orphaned references this sweep. A rising rate
	// means the DB delete keeps failing; the rows persist until a later sweep succeeds.
	RetentionMetadataCleanupFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nirvet_retention_metadata_cleanup_failures_total",
		Help: "raw_events rows whose blob was deleted but whose metadata-row delete failed (orphaned this sweep).",
	})

	// RetentionRowsWithMissingBlob is the current number of raw_events rows whose blob is confirmed gone but
	// whose metadata row is still present (pending self-heal). Steady-state should be ~0; a persistent non-zero
	// value means a stuck deletion an operator must investigate.
	RetentionRowsWithMissingBlob = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "nirvet_retention_rows_with_missing_blob",
		Help: "raw_events rows whose payload blob is gone but whose metadata row still exists (pending cleanup).",
	})

	// RetentionOldestPendingCleanupSeconds is the age of the oldest not-yet-completed deletion attempt. It
	// should stay small (bounded by the sweep interval); a growing value means the ledger is not draining.
	RetentionOldestPendingCleanupSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "nirvet_retention_oldest_pending_cleanup_seconds",
		Help: "Age of the oldest incomplete retention deletion attempt (0 when the ledger is clean).",
	})
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Middleware records per-request metrics. It reads the matched route template
// (r.Pattern, set by the router) after the handler runs, so labels stay low
// cardinality (no per-UUID paths).
func Middleware() httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			httpRequests.WithLabelValues(r.Method, route, strconv.Itoa(rec.status)).Inc()
			httpDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
		})
	}
}

// Handler serves the Prometheus scrape endpoint.
func Handler() http.Handler { return promhttp.Handler() }
