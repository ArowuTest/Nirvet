package queue

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// New selects the queue backend (ADR-0003): NATS/JetStream when a URL is
// configured, otherwise the Postgres MVP queue. Returns the queue, a closer to
// call on shutdown, the backend name (for logging), and any error. Callers depend
// only on the Queue interface, so the choice is invisible to the ingestion worker.
func New(ctx context.Context, natsURL string, pool *pgxpool.Pool) (Queue, func(), string, error) {
	if natsURL != "" {
		q, err := NewNATS(ctx, natsURL)
		if err != nil {
			return nil, nil, "nats", err
		}
		return q, q.Close, "nats", nil
	}
	return NewPostgres(pool), func() {}, "postgres", nil
}
