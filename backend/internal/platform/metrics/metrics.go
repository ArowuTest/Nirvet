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
