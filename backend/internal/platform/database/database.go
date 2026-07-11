// Package database provides the PostgreSQL pool and the tenant-context
// transaction helpers that enforce Row-Level Security (ADR-0001).
//
// The application connects as a NON-owner, NON-BYPASSRLS role. Every access to
// tenant-owned data MUST go through WithTenant, which sets app.current_tenant as
// a transaction-local GUC so RLS policies scope every row to the tenant.
package database

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// envInt reads an integer env var, falling back to def when unset or unparseable.
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// DB wraps a pgx pool with tenant-aware helpers.
type DB struct {
	Pool *pgxpool.Pool
}

// Connect opens the pool and verifies connectivity.
func Connect(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("database: parse dsn: %w", err)
	}
	// Pool size is configurable (external-review): a fixed 10 becomes a bottleneck once API replicas,
	// worker pools, pollers, SLA sweepers and notification dispatchers all draw from it. A DSN that carries
	// `pool_max_conns` wins (ParseConfig already applied it); otherwise take NIRVET_DB_MAX_CONNS (default 10).
	if !strings.Contains(dsn, "pool_max_conns") {
		if n := envInt("NIRVET_DB_MAX_CONNS", 10); n > 0 {
			cfg.MaxConns = int32(n)
		}
	}
	cfg.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("database: connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: ping: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Close releases the pool.
func (db *DB) Close() { db.Pool.Close() }

// Health pings the database.
func (db *DB) Health(ctx context.Context) error {
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return db.Pool.Ping(c)
}

// TxFunc runs inside a transaction. It receives the tenant-scoped tx.
type TxFunc func(ctx context.Context, tx pgx.Tx) error

// WithTenant runs fn in a transaction with app.current_tenant set to tenantID.
// RLS policies then constrain every statement to that tenant.
//
// set_config(..., true) makes the setting transaction-local (like SET LOCAL) and
// is parameterised, so it is safe under transaction-pooling connection poolers
// where a session-level SET would leak across clients.
func (db *DB) WithTenant(ctx context.Context, tenantID uuid.UUID, fn TxFunc) error {
	return db.runTx(ctx, tenantID.String(), fn)
}

// WithSystem runs fn in a transaction WITHOUT a tenant context. Use only for
// platform-level, non-tenant tables (e.g. the tenants registry itself) or
// SECURITY DEFINER auth lookups. Tenant-owned tables remain protected by RLS
// and will return nothing here.
func (db *DB) WithSystem(ctx context.Context, fn TxFunc) error {
	return db.runTx(ctx, "", fn)
}

func (db *DB) runTx(ctx context.Context, tenant string, fn TxFunc) (err error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("database: begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	if tenant != "" {
		// Transaction-local tenant GUC read by RLS policies.
		if _, err = tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenant); err != nil {
			return fmt.Errorf("database: set tenant: %w", err)
		}
	}

	if err = fn(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("database: commit: %w", err)
	}
	return nil
}
