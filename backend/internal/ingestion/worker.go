package ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/metrics"
	"github.com/ArowuTest/nirvet/internal/platform/queue"
	"github.com/ArowuTest/nirvet/internal/platform/safe"
	"github.com/ArowuTest/nirvet/internal/platform/tracing"
	"github.com/ArowuTest/nirvet/internal/threatintel"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// workerTracer instruments the async ingest→detect→correlate pipeline (GC-4). Each job gets a trace so a
// stuck or slow event can be followed across the three stages; a no-op when tracing is disabled.
var workerTracer = tracing.Tracer("nirvet/ingest-worker")

// Correlator clusters a raised alert with related alerts and returns the cluster id
// plus the alert's individual risk (SRS §6.7). Implemented by correlation.Service;
// a narrow interface so ingestion does not depend on the correlation package.
type Correlator interface {
	Correlate(ctx context.Context, tenantID uuid.UUID, entity, severity string, mitre []string, confidence int) (correlationID uuid.UUID, alertRisk int, err error)
}

// Worker normalizes raw events into the EventStore and runs detection. It runs at
// the system level (spans tenants); each job applies its own tenant context.
// Pipeline per event: normalize -> enrich (threat intel) -> store -> detect -> correlate.
type Worker struct {
	q          queue.Queue
	events     eventstore.EventStore
	enricher   *threatintel.Enricher
	detector   *detection.Engine
	alerts     *alert.Service
	correlator Correlator
	quality    *NormQuality // §6.5: normalization data-quality recorder (optional)
	log        *slog.Logger
	batch      int
}

// NewWorker builds the ingestion worker.
func NewWorker(q queue.Queue, events eventstore.EventStore, enricher *threatintel.Enricher, detector *detection.Engine, alerts *alert.Service, log *slog.Logger) *Worker {
	return &Worker{q: q, events: events, enricher: enricher, detector: detector, alerts: alerts, log: log, batch: 20}
}

// WithNormQuality wires the normalization data-quality recorder (NORM-003/009).
func (wk *Worker) WithNormQuality(q *NormQuality) *Worker { wk.quality = q; return wk }

// WithCorrelator wires alert correlation + risk scoring (best-effort per alert).
func (wk *Worker) WithCorrelator(c Correlator) *Worker { wk.correlator = c; return wk }

// Start runs the worker loop until ctx is cancelled.
func (wk *Worker) Start(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// R6: guard the whole tick like the reconciler/reaper loops — per-job panics are already
			// recovered in processGuarded, this covers a panic in Claim/Complete/Fail so the worker
			// goroutine survives and keeps draining the queue.
			safe.Do(wk.log, "ingest-worker", func() {
				if _, err := wk.RunOnce(ctx); err != nil {
					wk.log.Error("ingest worker error", "err", err)
				}
			})
		}
	}
}

// RunOnce claims and processes one batch of jobs.
func (wk *Worker) RunOnce(ctx context.Context) (int, error) {
	jobs, err := wk.q.Claim(ctx, wk.batch)
	if err != nil {
		return 0, err
	}
	for _, j := range jobs {
		if err := wk.processGuarded(ctx, j); err != nil {
			wk.log.Warn("normalize failed; retry/dead-letter", "job", j.ID, "err", err)
			_ = wk.q.Fail(ctx, j.ID, err.Error())
			continue
		}
		_ = wk.q.Complete(ctx, j.ID)
	}
	// §6.5: flush the batch's accumulated normalization-quality deltas once (not per event).
	// Best-effort — a failed flush re-accumulates and retries on the next batch.
	if wk.quality != nil && len(jobs) > 0 {
		if err := wk.quality.Flush(ctx); err != nil {
			wk.log.Warn("normalization quality flush failed", "err", err)
		}
	}
	return len(jobs), nil
}

// processGuarded runs process with panic recovery so one poison event (a nil
// dereference in a normalizer, a malformed vendor payload) cannot crash the worker
// goroutine and halt ingestion for every tenant. A recovered panic is converted to
// an error, so the job follows the normal retry/dead-letter path instead of taking
// the process down.
func (wk *Worker) processGuarded(ctx context.Context, j queue.Job) (err error) {
	defer func() {
		if r := recover(); r != nil {
			wk.log.Error("ingest worker recovered from panic; job will retry/dead-letter",
				"job", j.ID, "panic", r)
			err = fmt.Errorf("panic processing job: %v", r)
		}
	}()
	return wk.process(ctx, j)
}

// mitreFromData extracts ATT&CK technique ids from data.mitre, which normalizers
// set as either []string or []any (JSON-decoded).
func mitreFromData(data map[string]any) []string {
	switch v := data["mitre"].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func (wk *Worker) process(ctx context.Context, j queue.Job) (err error) {
	ctx, span := workerTracer.Start(ctx, "ingest.process_job", trace.WithAttributes(
		attribute.String("nirvet.tenant_id", j.TenantID.String()),
		attribute.String("nirvet.job_id", j.ID.String()),
	))
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	var nj normalizeJob
	if err := json.Unmarshal(j.Payload, &nj); err != nil {
		return err // malformed -> dead-letters after retries (parser error queue)
	}
	in := Normalize(nj.Input) // source-aware mapping to the canonical event shape
	span.SetAttributes(attribute.String("nirvet.source", in.Source), attribute.String("nirvet.event_class", in.ClassName))
	observed := in.ObservedAt
	if observed.IsZero() {
		observed = time.Now()
	}
	ev := eventstore.NormalizedEvent{
		ID:            uuid.New(),
		TenantID:      j.TenantID,
		SchemaVersion: eventstore.CanonicalSchemaVersion, // ADR-0006
		DedupeKey:     nj.DedupeKey,
		Source:        in.Source,
		CollectedAt:   time.Now(),
		ObservedAt:    observed,
		ClassName:     in.ClassName,
		ActivityName:  in.ActivityName,
		Severity:      in.Severity,
		Confidence:    in.Confidence,
		ActorRef:      in.ActorRef,
		TargetRef:     in.TargetRef,
		Action:        in.Action,
		Outcome:       in.Outcome,
		RawPointer:    "raw_events:" + nj.RawID.String(),
		Checksum:      nj.Checksum,
		Data:          in.Data,
	}
	// Promote the canonical hot fields to first-class columns (ADR-0006 v1.1).
	ev.MITRE = mitreFromData(in.Data)
	if v, ok := in.Data["vendor"].(string); ok {
		ev.Vendor = v
	}
	if p, ok := in.Data["product"].(string); ok {
		ev.Product = p
	}
	// R6-C1: final canonical-severity clamp before the event reaches the events CHECK constraint. A
	// vendor mapper may set a non-canonical severity verbatim (overwriting the early normalize); rather
	// than let that dead-letter a legitimate security event, coerce to the canonical floor and log.
	if !isCanonicalSeverity(ev.Severity) {
		orig := ev.Severity
		ev.Severity = normalizeSeverity(ev.Severity)
		wk.log.Warn("coerced non-canonical event severity", "original", orig, "coerced", ev.Severity, "source", ev.Source)
	}
	// Enrichment: annotate the event with threat-intel watchlist hits before it is
	// stored and evaluated by detection.
	if wk.enricher != nil {
		if matches, _ := wk.enricher.Enrich(ctx, j.TenantID, []string{ev.ActorRef, ev.TargetRef, ev.Source}); len(matches) > 0 {
			vals := make([]string, 0, len(matches))
			detail := make([]map[string]any, 0, len(matches))
			maxScore := 0
			for _, m := range matches {
				vals = append(vals, m.Value)
				// Structured provenance so downstream (correlation COR-002, analyst triage) can see
				// WHY a hit matters: source, matched STIX object, confidence, labels, kill-chain (TI-004).
				d := map[string]any{"source": m.Source, "value": m.Value, "tlp": m.TLP, "score": m.Score}
				if m.ObjectID != "" {
					d["object_id"] = m.ObjectID
				}
				if len(m.Labels) > 0 {
					d["labels"] = m.Labels
				}
				if len(m.KillChain) > 0 {
					d["kill_chain"] = m.KillChain
				}
				detail = append(detail, d)
				if m.Score > maxScore {
					maxScore = m.Score
				}
			}
			if ev.Data == nil {
				ev.Data = map[string]any{}
			}
			ev.Data["threat_intel_hits"] = vals
			ev.Data["threat_intel_matches"] = detail
			if maxScore > ev.Confidence {
				ev.Confidence = maxScore
			}
		}
	}
	inserted, err := wk.events.Append(ctx, j.TenantID, []eventstore.NormalizedEvent{ev})
	if err != nil {
		return err
	}
	// Idempotency: if the event already existed (duplicate ingest or job retry),
	// do not run detection again — this makes the whole worker safe under
	// at-least-once delivery.
	if inserted == 0 {
		return nil
	}
	// §6.5: record this (genuinely new) event's normalization quality — parser + how completely it
	// mapped (stamped by Normalize). Accumulated in memory; flushed once per RunOnce batch.
	if wk.quality != nil {
		parser, _ := in.Data["parser"].(string)
		pv, _ := in.Data["parser_version"].(int)
		conf, _ := in.Data["normalization_confidence"].(int)
		wk.quality.Record(j.TenantID, in.Source, parser, pv, conf)
	}
	// Detection runs the rule catalogue (module: detection) via the injected
	// evaluator, producing zero or more alerts (each idempotent on its dedupe key).
	return wk.detect(ctx, ev)
}

// detect evaluates the event against the tenant's rule catalogue and raises an alert per matching rule.
// Each alert is idempotent on <event dedupe key>:rule_id. Keying on the event's DETERMINISTIC content
// dedupe key — not its random per-normalization UUID — means two duplicates of the same event collapse to
// ONE alert on (tenant, dedupe_key) even if they reached detection as distinct rows: the ClickHouse event
// store's ReplacingMergeTree dedup is ASYNCHRONOUS (two concurrent workers can both insert + both detect),
// and a reconciler re-normalize could re-run detection. The Postgres store is already protected upstream
// (Append ON CONFLICT → inserted==0 → detection skipped), so this makes the alert layer robust regardless
// of the event-store backend or worker count (external-reviewer finding, ClickHouse alert-amplification).
func (wk *Worker) detect(ctx context.Context, ev eventstore.NormalizedEvent) (err error) {
	ctx, span := workerTracer.Start(ctx, "ingest.detect", trace.WithAttributes(
		attribute.String("nirvet.tenant_id", ev.TenantID.String()),
		attribute.String("nirvet.source", ev.Source),
	))
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	matches, err := wk.detector.Evaluate(ctx, ev.TenantID, ev)
	if err != nil {
		return err
	}
	span.SetAttributes(attribute.Int("nirvet.detection_matches", len(matches)))
	// The deterministic content key; fall back to the event id only when an event carries no dedupe key.
	alertKey := ev.ID.String()
	if ev.DedupeKey != "" {
		alertKey = ev.DedupeKey
	}
	for _, m := range matches {
		ruleID := m.RuleID
		title := m.RuleName
		if ev.TargetRef != "" {
			title += " — " + ev.TargetRef
		} else if ev.ActorRef != "" {
			title += " — " + ev.ActorRef
		}
		spec := alert.Spec{
			Title:       title,
			Severity:    m.Severity,
			Confidence:  m.Confidence,
			DedupeKey:   alertKey + ":" + m.RuleID.String(),
			DetectionID: &ruleID,
			MITRE:       m.MITRE,
		}
		a, inserted, err := wk.alerts.CreateFromEvent(ctx, ev, spec)
		if err != nil {
			return err
		}
		if inserted {
			metrics.AlertsRaised.Inc()
			wk.correlate(ctx, ev, a)
		}
	}
	return nil
}

// correlate clusters a newly-raised alert with related alerts on the same entity
// and records the alert's risk (§6.7). Best-effort: a correlation failure never
// blocks the detection pipeline.
func (wk *Worker) correlate(ctx context.Context, ev eventstore.NormalizedEvent, a *alert.Alert) {
	if wk.correlator == nil {
		return
	}
	ctx, span := workerTracer.Start(ctx, "ingest.correlate", trace.WithAttributes(
		attribute.String("nirvet.tenant_id", ev.TenantID.String()),
		attribute.String("nirvet.alert_id", a.ID.String()),
	))
	defer span.End()

	entity := ev.TargetRef
	if entity == "" {
		entity = ev.ActorRef
	}
	cid, risk, err := wk.correlator.Correlate(ctx, ev.TenantID, entity, a.Severity, a.MITRE, a.Confidence)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		wk.log.Warn("correlation failed", "alert", a.ID, "err", err)
		return
	}
	span.SetAttributes(attribute.Int("nirvet.alert_risk", risk))
	var cptr *uuid.UUID
	if cid != uuid.Nil {
		cptr = &cid
	}
	_ = wk.alerts.SetCorrelation(ctx, ev.TenantID, a.ID, cptr, risk)
}
