package eventstore

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/database"
)

// New selects the telemetry backend (ADR-0002): ClickHouse when a DSN is
// configured, otherwise the Postgres MVP store. Returns the store, a closer to
// call on shutdown, the backend name (for logging), and any error. Callers depend
// only on the EventStore interface, so the choice is invisible downstream.
func New(ctx context.Context, clickhouseDSN string, pg *database.DB) (EventStore, func() error, string, error) {
	if clickhouseDSN != "" {
		s, err := NewClickHouse(ctx, clickhouseDSN)
		if err != nil {
			return nil, nil, "clickhouse", err
		}
		return s, s.Close, "clickhouse", nil
	}
	return NewPostgres(pg), func() error { return nil }, "postgres", nil
}
