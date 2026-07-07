package tracing

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// statusRecorder captures the response status for span/attribute annotation.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Middleware starts a server span per request. The span is named after the Go
// 1.22 route template (r.Pattern), which is only known once the mux has matched,
// so it is set after the handler runs (same approach as the metrics middleware).
// Inbound W3C trace context is honoured so a caller's trace continues here.
// No-op cost when tracing is disabled (the global tracer is a no-op provider).
func Middleware() httpx.Middleware {
	tr := otel.Tracer("nirvet/http")
	prop := otel.GetTextMapPropagator()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := prop.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			ctx, span := tr.Start(ctx, r.Method,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					attribute.String("http.request.method", r.Method),
					attribute.String("nirvet.request_id", httpx.RequestIDFrom(r.Context())),
				),
			)
			defer span.End()

			// Reassign r so the traced context AND the router-set route template
			// (r.Pattern, populated in place by ServeMux) are read from one object.
			r = r.WithContext(ctx)
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			// r.Pattern is the matched route template and already carries the method,
			// e.g. "POST /incidents/{id}/assign" — low cardinality, ideal span name.
			// Fall back to "METHOD path" only when nothing matched (404).
			route := r.Pattern
			name := route
			if route == "" {
				route = r.URL.Path
				name = r.Method + " " + route
			}
			span.SetName(name)
			span.SetAttributes(
				attribute.String("http.route", route),
				attribute.Int("http.response.status_code", rec.status),
			)
			if rec.status >= 500 {
				span.SetStatus(codes.Error, http.StatusText(rec.status))
			}
		})
	}
}
