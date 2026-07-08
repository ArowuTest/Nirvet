package queue

// NATS JetStream queue backend, gated on NIRVET_NATS_URL. Proves the durable
// semantics the ingestion worker relies on: claim→complete acks (no redelivery),
// claim→fail redelivers with an incremented attempt count, and a job is
// dead-lettered after MaxAttempts (never silently lost, never looped forever).

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func setupNATS(t *testing.T) *NATSQueue {
	t.Helper()
	url := os.Getenv("NIRVET_NATS_URL")
	if url == "" {
		t.Skip("set NIRVET_NATS_URL to run NATS queue tests")
	}
	ctx := context.Background()
	// Purge any leftover messages for a deterministic slate.
	if nc, err := nats.Connect(url); err == nil {
		if js, jerr := jetstream.New(nc); jerr == nil {
			if s, serr := js.Stream(ctx, natsStream); serr == nil {
				_ = s.Purge(ctx)
			}
		}
		nc.Close()
	}
	q, err := NewNATS(ctx, url)
	if err != nil {
		t.Fatalf("NewNATS: %v", err)
	}
	q.backoff = 100 * time.Millisecond // fast redelivery for the test
	t.Cleanup(q.Close)
	return q
}

func claimOne(t *testing.T, q *NATSQueue) (Job, bool) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		jobs, err := q.Claim(ctx, 10)
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		if len(jobs) > 0 {
			return jobs[0], true
		}
		time.Sleep(80 * time.Millisecond)
	}
	return Job{}, false
}

func TestNATS_EnqueueClaimComplete(t *testing.T) {
	q := setupNATS(t)
	ctx := context.Background()
	tenant := uuid.New()
	if err := q.Enqueue(ctx, tenant, "normalize", []byte("hello")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	job, ok := claimOne(t, q)
	if !ok {
		t.Fatal("expected to claim the enqueued job")
	}
	if job.TenantID != tenant || job.Kind != "normalize" || string(job.Payload) != "hello" || job.Attempts != 1 {
		t.Fatalf("job round-trip wrong: %+v", job)
	}
	if err := q.Complete(ctx, job.ID); err != nil {
		t.Fatalf("complete: %v", err)
	}
	// After ack the message must NOT be redelivered.
	if _, ok := claimOne(t, q); ok {
		t.Fatal("completed job must not be redelivered")
	}
}

func TestNATS_FailRedeliversWithAttempt(t *testing.T) {
	q := setupNATS(t)
	ctx := context.Background()
	if err := q.Enqueue(ctx, uuid.New(), "normalize", []byte("x")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	j1, ok := claimOne(t, q)
	if !ok || j1.Attempts != 1 {
		t.Fatalf("first claim: ok=%v attempts=%d", ok, j1.Attempts)
	}
	if err := q.Fail(ctx, j1.ID, "boom"); err != nil {
		t.Fatalf("fail: %v", err)
	}
	j2, ok := claimOne(t, q)
	if !ok {
		t.Fatal("failed job must be redelivered")
	}
	if j2.ID != j1.ID || j2.Attempts != 2 {
		t.Fatalf("redelivery wrong: id-eq=%v attempts=%d", j2.ID == j1.ID, j2.Attempts)
	}
	_ = q.Complete(ctx, j2.ID)
}

func TestNATS_DeadLettersAfterMaxAttempts(t *testing.T) {
	q := setupNATS(t)
	ctx := context.Background()
	if err := q.Enqueue(ctx, uuid.New(), "normalize", []byte("poison")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// Fail it MaxAttempts times; after the last, it must be dead-lettered.
	for i := 0; i < MaxAttempts; i++ {
		job, ok := claimOne(t, q)
		if !ok {
			t.Fatalf("delivery %d: expected redelivery", i+1)
		}
		if err := q.Fail(ctx, job.ID, "still failing"); err != nil {
			t.Fatalf("fail %d: %v", i+1, err)
		}
	}
	// No further redelivery.
	if _, ok := claimOne(t, q); ok {
		t.Fatal("job must be dead-lettered after MaxAttempts, not redelivered forever")
	}
}
