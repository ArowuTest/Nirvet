// Package tracing provides distributed tracing (NFR-007 observability, DoD #9)
// built on OpenTelemetry — the vendor-neutral standard, so the backend stays
// portable (ADR-0005): the OTLP endpoint is swappable local -> GCP Cloud Trace /
// any collector with no code change.
//
// Design: tracing is OFF by default. With no OTLP endpoint configured, Init
// installs only the W3C TraceContext propagators and leaves the global no-op
// tracer provider in place — zero overhead, no network, safe for local and
// offline runs. Set an endpoint to turn on batched span export. Tracing is
// always fail-open: a tracing error never breaks a request.
package tracing

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Config controls tracing setup.
type Config struct {
	ServiceName  string // e.g. "nirvet-api" | "nirvet-worker"
	ServiceVer   string
	Environment  string // development | staging | production
	OTLPEndpoint string // empty => no-op (tracing disabled)
}

// Shutdown flushes and stops the tracer provider. Always safe to call.
type Shutdown func(context.Context) error

// Init wires the global tracer provider and propagators. It returns a Shutdown
// that flushes pending spans. When cfg.OTLPEndpoint is empty, tracing is a no-op
// but context propagation is still installed (so inbound trace headers are
// honoured and outbound ones set once an exporter is later enabled).
func Init(ctx context.Context, cfg Config) (Shutdown, error) {
	// Propagators are cheap and useful even without an exporter.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	if cfg.OTLPEndpoint == "" {
		// Disabled: leave the default no-op provider. Nothing to flush.
		return func(context.Context) error { return nil }, nil
	}

	exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(cfg.OTLPEndpoint))
	if err != nil {
		return nil, err
	}
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(cfg.ServiceName),
		semconv.ServiceVersion(cfg.ServiceVer),
		semconv.DeploymentEnvironment(cfg.Environment),
	))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

// Tracer returns a named tracer from the global provider (no-op if disabled).
func Tracer(name string) trace.Tracer { return otel.Tracer(name) }

// SpanContextFrom returns the trace and span IDs for the current context, or
// empty strings if there is no recording span. Used to correlate logs with traces.
func SpanContextFrom(ctx context.Context) (traceID, spanID string) {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return "", ""
	}
	return sc.TraceID().String(), sc.SpanID().String()
}
