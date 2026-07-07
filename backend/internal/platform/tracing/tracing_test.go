package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// Disabled tracing must be a genuine no-op: no error, a callable shutdown, and no
// recording span (so trace IDs are empty and there is zero export overhead).
func TestInit_NoopWhenDisabled(t *testing.T) {
	shutdown, err := Init(context.Background(), Config{ServiceName: "test", OTLPEndpoint: ""})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown must not be nil")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if tid, _ := SpanContextFrom(context.Background()); tid != "" {
		t.Fatalf("expected empty trace id with tracing disabled, got %q", tid)
	}
}

// The middleware must name the server span by the METHOD + route TEMPLATE (not the
// concrete path — that would be high-cardinality) and record the response status.
func TestMiddleware_NamesSpanByRouteTemplate(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	mux := http.NewServeMux()
	mux.HandleFunc("POST /incidents/{id}/assign", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware()(mux)

	req := httptest.NewRequest(http.MethodPost, "/incidents/1f2e/assign", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if got, want := spans[0].Name(), "POST /incidents/{id}/assign"; got != want {
		t.Fatalf("span name = %q, want %q (low-cardinality route template)", got, want)
	}
	var sawRoute, sawStatus bool
	for _, a := range spans[0].Attributes() {
		switch a.Key {
		case "http.route":
			sawRoute = a.Value.AsString() == "POST /incidents/{id}/assign"
		case "http.response.status_code":
			sawStatus = a.Value.AsInt64() == http.StatusOK
		}
	}
	if !sawRoute || !sawStatus {
		t.Fatalf("missing route/status attributes: route=%v status=%v", sawRoute, sawStatus)
	}
}

// A 5xx response must mark the span as an error so failures are findable in a trace.
func TestMiddleware_MarksServerErrors(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	Middleware()(mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/boom", nil))

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Status().Code.String() != "Error" {
		t.Fatalf("expected span status Error for 500, got %s", spans[0].Status().Code)
	}
}
