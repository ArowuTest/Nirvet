package ingestion

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/metrics"
	"github.com/ArowuTest/nirvet/internal/platform/queue"
	"github.com/ArowuTest/nirvet/internal/threatintel"
	"github.com/google/uuid"
)

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
	log        *slog.Logger
	batch      int
}

// NewWorker builds the ingestion worker.
func NewWorker(q queue.Queue, events eventstore.EventStore, enricher *threatintel.Enricher, detector *detection.Engine, alerts *alert.Service, log *slog.Logger) *Worker {
	return &Worker{q: q, events: events, enricher: enricher, detector: detector, alerts: alerts, log: log, batch: 20}
}

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
			if _, err := wk.RunOnce(ctx); err != nil {
				wk.log.Error("ingest worker error", "err", err)
			}
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
		if err := wk.process(ctx, j); err != nil {
			wk.log.Warn("normalize failed; retry/dead-letter", "job", j.ID, "err", err)
			_ = wk.q.Fail(ctx, j.ID, err.Error())
			continue
		}
		_ = wk.q.Complete(ctx, j.ID)
	}
	return len(jobs), nil
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

func (wk *Worker) process(ctx context.Context, j queue.Job) error {
	var nj normalizeJob
	if err := json.Unmarshal(j.Payload, &nj); err != nil {
		return err // malformed -> dead-letters after retries (parser error queue)
	}
	in := Normalize(nj.Input) // source-aware mapping to the canonical event shape
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
	// Enrichment: annotate the event with threat-intel watchlist hits before it is
	// stored and evaluated by detection.
	if wk.enricher != nil {
		if matches, _ := wk.enricher.Enrich(ctx, j.TenantID, []string{ev.ActorRef, ev.TargetRef, ev.Source}); len(matches) > 0 {
			vals := make([]string, 0, len(matches))
			maxScore := 0
			for _, m := range matches {
				vals = append(vals, m.Value)
				if m.Score > maxScore {
					maxScore = m.Score
				}
			}
			if ev.Data == nil {
				ev.Data = map[string]any{}
			}
			ev.Data["threat_intel_hits"] = vals
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
	// Detection runs the rule catalogue (module: detection) via the injected
	// evaluator, producing zero or more alerts (each idempotent on its dedupe key).
	return wk.detect(ctx, ev)
}

// detect evaluates the event against the tenant's rule catalogue and raises an
// alert per matching rule. Each alert is idempotent on event_id:rule_id, so a
// reprocessed event never duplicates alerts.
func (wk *Worker) detect(ctx context.Context, ev eventstore.NormalizedEvent) error {
	matches, err := wk.detector.Evaluate(ctx, ev.TenantID, ev)
	if err != nil {
		return err
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
			DedupeKey:   ev.ID.String() + ":" + m.RuleID.String(),
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
	entity := ev.TargetRef
	if entity == "" {
		entity = ev.ActorRef
	}
	cid, risk, err := wk.correlator.Correlate(ctx, ev.TenantID, entity, a.Severity, a.MITRE, a.Confidence)
	if err != nil {
		wk.log.Warn("correlation failed", "alert", a.ID, "err", err)
		return
	}
	var cptr *uuid.UUID
	if cid != uuid.Nil {
		cptr = &cid
	}
	_ = wk.alerts.SetCorrelation(ctx, ev.TenantID, a.ID, cptr, risk)
}
