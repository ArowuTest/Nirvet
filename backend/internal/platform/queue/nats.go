package queue

// NATS JetStream queue backend (ADR-0003 scaling backend). Same Queue interface as
// the Postgres MVP queue, so nothing downstream changes — the ingestion worker is
// unaware of the backend. Selected once the queue needs to fan out beyond a single
// Postgres (see build/ARCHITECTURE_GATES.md scaling sequence: NATS after Redis).
//
// Semantics mapping:
//   - Enqueue  -> publish to the ingest subject (Job.ID as Nats-Msg-Id for dedup).
//   - Claim(n) -> pull-fetch up to n messages; each is held in-flight, keyed by
//     Job.ID, so the correct message can later be ack'd/nak'd.
//   - Complete -> Ack the in-flight message.
//   - Fail     -> NakWithDelay (redelivery + backoff) until MaxAttempts, then Term
//     (dead-letter: JetStream stops redelivering). A security event is never lost.
// Delivery is at-least-once; consumers are idempotent (upstream dedupe_key).

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	natsStream  = "NIRVET_INGEST"
	natsSubject = "nirvet.ingest.jobs"
	natsDurable = "ingest-worker"
)

// jobMsg is the wire form of a Job on the stream.
type jobMsg struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Kind     string    `json:"kind"`
	Payload  []byte    `json:"payload"`
}

// NATSQueue is a JetStream-backed durable queue.
type NATSQueue struct {
	nc       *nats.Conn
	js       jetstream.JetStream
	cons     jetstream.Consumer
	backoff  time.Duration
	mu       sync.Mutex
	inflight map[uuid.UUID]jetstream.Msg
}

// NewNATS connects, ensures the stream + durable pull consumer exist, and returns
// the queue. Call Close on shutdown.
func NewNATS(ctx context.Context, url string) (*NATSQueue, error) {
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	if _, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:       natsStream,
		Subjects:   []string{natsSubject},
		Duplicates: 2 * time.Minute, // Nats-Msg-Id dedup window
	}); err != nil {
		nc.Close()
		return nil, err
	}
	cons, err := js.CreateOrUpdateConsumer(ctx, natsStream, jetstream.ConsumerConfig{
		Durable:    natsDurable,
		AckPolicy:  jetstream.AckExplicitPolicy,
		MaxDeliver: MaxAttempts,
		AckWait:    30 * time.Second,
	})
	if err != nil {
		nc.Close()
		return nil, err
	}
	return &NATSQueue{
		nc: nc, js: js, cons: cons,
		backoff:  backoffSeconds * time.Second,
		inflight: map[uuid.UUID]jetstream.Msg{},
	}, nil
}

// Close drains and closes the connection.
func (q *NATSQueue) Close() {
	if q.nc != nil {
		q.nc.Close()
	}
}

// Enqueue publishes a job (dedup on Job.ID within the stream's duplicate window).
func (q *NATSQueue) Enqueue(ctx context.Context, tenantID uuid.UUID, kind string, payload []byte) error {
	jm := jobMsg{ID: uuid.New(), TenantID: tenantID, Kind: kind, Payload: payload}
	data, err := json.Marshal(jm)
	if err != nil {
		return err
	}
	_, err = q.js.Publish(ctx, natsSubject, data, jetstream.WithMsgID(jm.ID.String()))
	return err
}

// Claim pull-fetches up to n jobs, holding each in-flight so it can be ack'd/nak'd.
func (q *NATSQueue) Claim(ctx context.Context, n int) ([]Job, error) {
	batch, err := q.cons.Fetch(n, jetstream.FetchMaxWait(500*time.Millisecond))
	if err != nil {
		return nil, err
	}
	var jobs []Job
	for msg := range batch.Messages() {
		var jm jobMsg
		if err := json.Unmarshal(msg.Data(), &jm); err != nil {
			_ = msg.Term() // poison message — never redeliver a payload we can't parse
			continue
		}
		attempts := 1
		if md, merr := msg.Metadata(); merr == nil {
			attempts = int(md.NumDelivered)
		}
		q.mu.Lock()
		q.inflight[jm.ID] = msg
		q.mu.Unlock()
		jobs = append(jobs, Job{ID: jm.ID, TenantID: jm.TenantID, Kind: jm.Kind, Payload: jm.Payload, Attempts: attempts})
	}
	return jobs, batch.Error()
}

// take removes and returns the in-flight message for a job id (nil if unknown).
func (q *NATSQueue) take(id uuid.UUID) jetstream.Msg {
	q.mu.Lock()
	defer q.mu.Unlock()
	msg := q.inflight[id]
	delete(q.inflight, id)
	return msg
}

// Complete acks the job's message.
func (q *NATSQueue) Complete(ctx context.Context, id uuid.UUID) error {
	msg := q.take(id)
	if msg == nil {
		return nil
	}
	return msg.Ack()
}

// Fail naks with backoff for redelivery; after MaxAttempts it terminates the
// message (dead-letter — JetStream stops redelivering).
func (q *NATSQueue) Fail(ctx context.Context, id uuid.UUID, reason string) error {
	msg := q.take(id)
	if msg == nil {
		return nil
	}
	if md, err := msg.Metadata(); err == nil && md.NumDelivered >= uint64(MaxAttempts) {
		return msg.Term()
	}
	return msg.NakWithDelay(q.backoff)
}
