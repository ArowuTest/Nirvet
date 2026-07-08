package eventstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

// ClickHouseStore is the V1 telemetry backend (ADR-0002): a columnar hot store for
// high-volume security events. It satisfies the same EventStore interface as the
// Postgres MVP store, so nothing downstream (detection/search) changes.
//
// Tenant isolation: ClickHouse has no RLS, so EVERY query carries a mandatory
// tenant_id predicate (ADR-0002) and the table is ORDER BY (tenant_id, dedupe_key)
// so that predicate is also the primary-key prefix (fast + isolated).
//
// Idempotency: ClickHouse inserts are append-only, so Append pre-filters dedupe
// keys already present for the tenant and inserts only new ones (returning the new
// count, matching the Postgres semantics the pipeline relies on). A
// ReplacingMergeTree(collected_at) keyed on (tenant_id, dedupe_key) is the backstop
// that collapses any duplicate that slips through the pre-filter race window.
type ClickHouseStore struct {
	conn  driver.Conn
	table string
}

// NewClickHouse connects, verifies, and ensures the events table exists.
func NewClickHouse(ctx context.Context, dsn string) (*ClickHouseStore, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("clickhouse dsn: %w", err)
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}
	s := &ClickHouseStore{conn: conn, table: "events"}
	if err := s.migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Close releases the connection.
func (s *ClickHouseStore) Close() error { return s.conn.Close() }

func (s *ClickHouseStore) migrate(ctx context.Context) error {
	if err := s.conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS events (
		id            UUID,
		tenant_id     UUID,
		schema_version LowCardinality(String) DEFAULT '1.0',
		dedupe_key   String,
		source       String,
		connector_id Nullable(UUID),
		collected_at DateTime64(3),
		observed_at  DateTime64(3),
		class_name   String,
		activity_name String,
		severity     LowCardinality(String),
		confidence   Int32,
		actor_ref    String,
		target_ref   String,
		action       String,
		outcome      String,
		mitre        Array(String),
		vendor       LowCardinality(String),
		product      LowCardinality(String),
		raw_pointer  String,
		checksum     String,
		data         String
	) ENGINE = ReplacingMergeTree(collected_at)
	  ORDER BY (tenant_id, dedupe_key)`); err != nil {
		return err
	}
	// Additive: bring a pre-existing table up to the current schema (ADR-0006).
	for _, alter := range []string{
		`ALTER TABLE events ADD COLUMN IF NOT EXISTS schema_version LowCardinality(String) DEFAULT '1.0'`,
		`ALTER TABLE events ADD COLUMN IF NOT EXISTS mitre Array(String)`,
		`ALTER TABLE events ADD COLUMN IF NOT EXISTS vendor LowCardinality(String)`,
		`ALTER TABLE events ADD COLUMN IF NOT EXISTS product LowCardinality(String)`,
	} {
		if err := s.conn.Exec(ctx, alter); err != nil {
			return err
		}
	}
	return nil
}

// Append inserts events for a tenant, idempotent on dedupe_key, returning the
// number newly inserted (duplicates skipped) so detection runs only on new events.
func (s *ClickHouseStore) Append(ctx context.Context, tenantID uuid.UUID, events []NormalizedEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	keys := make([]string, 0, len(events))
	for _, e := range events {
		if e.DedupeKey != "" {
			keys = append(keys, e.DedupeKey)
		}
	}
	existing := map[string]bool{}
	if len(keys) > 0 {
		rows, err := s.conn.Query(ctx,
			`SELECT dedupe_key FROM events WHERE tenant_id = ? AND dedupe_key IN ?`, tenantID, keys)
		if err != nil {
			return 0, fmt.Errorf("eventstore: dedupe lookup: %w", err)
		}
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return 0, err
			}
			existing[k] = true
		}
		rows.Close()
	}

	// Explicit column list so inserts are independent of physical column order
	// (ALTER ADD COLUMN appends at the end; a fresh CREATE has it inline).
	batch, err := s.conn.PrepareBatch(ctx, `INSERT INTO events
		(id, tenant_id, schema_version, dedupe_key, source, connector_id, collected_at, observed_at,
		 class_name, activity_name, severity, confidence, actor_ref, target_ref, action, outcome,
		 mitre, vendor, product, raw_pointer, checksum, data)`)
	if err != nil {
		return 0, fmt.Errorf("eventstore: prepare batch: %w", err)
	}
	inserted := 0
	seen := map[string]bool{}
	for _, e := range events {
		if e.DedupeKey != "" && (existing[e.DedupeKey] || seen[e.DedupeKey]) {
			continue
		}
		seen[e.DedupeKey] = true
		id := e.ID
		if id == uuid.Nil {
			id = uuid.New()
		}
		if e.CollectedAt.IsZero() {
			e.CollectedAt = time.Now()
		}
		data, err := json.Marshal(e.Data)
		if err != nil {
			data = []byte("{}")
		}
		sv := e.SchemaVersion
		if sv == "" {
			sv = CanonicalSchemaVersion
		}
		mitre := e.MITRE
		if mitre == nil {
			mitre = []string{}
		}
		if err := batch.Append(
			id, tenantID, sv, e.DedupeKey, e.Source, e.ConnectorID, e.CollectedAt, e.ObservedAt,
			e.ClassName, e.ActivityName, e.Severity, int32(e.Confidence),
			e.ActorRef, e.TargetRef, e.Action, e.Outcome, mitre, e.Vendor, e.Product, e.RawPointer, e.Checksum, string(data),
		); err != nil {
			_ = batch.Abort()
			return 0, fmt.Errorf("eventstore: batch append: %w", err)
		}
		inserted++
	}
	if err := batch.Send(); err != nil {
		return 0, fmt.Errorf("eventstore: batch send: %w", err)
	}
	return inserted, nil
}

// CountSince counts a tenant's events observed at or after `since`. The tenant_id
// predicate is mandatory (isolation, ADR-0002).
func (s *ClickHouseStore) CountSince(ctx context.Context, tenantID uuid.UUID, since time.Time) (int, error) {
	var n uint64
	if err := s.conn.QueryRow(ctx,
		`SELECT count() FROM events WHERE tenant_id = ? AND observed_at >= ?`, tenantID, since).Scan(&n); err != nil {
		return 0, err
	}
	return int(n), nil
}

// TopMITRE aggregates ATT&CK technique frequency for a tenant since `since`,
// array-joining the mitre column. The tenant_id predicate is mandatory (isolation).
func (s *ClickHouseStore) TopMITRE(ctx context.Context, tenantID uuid.UUID, since time.Time, limit int) ([]MITRECount, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.conn.Query(ctx,
		`SELECT technique, count() AS n
		   FROM events ARRAY JOIN mitre AS technique
		  WHERE tenant_id = ? AND observed_at >= ? AND technique != ''
		  GROUP BY technique ORDER BY n DESC LIMIT ?`, tenantID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MITRECount
	for rows.Next() {
		var m MITRECount
		var n uint64
		if err := rows.Scan(&m.Technique, &n); err != nil {
			return nil, err
		}
		m.Count = int(n)
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetByIDs returns the tenant's events with the given ids. The tenant_id predicate
// is applied first (isolation, ADR-0002); ids are matched with IN.
func (s *ClickHouseStore) GetByIDs(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) ([]NormalizedEvent, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := s.conn.Query(ctx,
		`SELECT id, tenant_id, schema_version, dedupe_key, source, connector_id, collected_at, observed_at,
		        class_name, activity_name, severity, confidence,
		        actor_ref, target_ref, action, outcome, mitre, vendor, product, raw_pointer, checksum, data
		   FROM events WHERE tenant_id = ? AND id IN (?) ORDER BY observed_at ASC`, tenantID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NormalizedEvent
	for rows.Next() {
		var e NormalizedEvent
		var data string
		var confidence int32
		if err := rows.Scan(&e.ID, &e.TenantID, &e.SchemaVersion, &e.DedupeKey, &e.Source, &e.ConnectorID,
			&e.CollectedAt, &e.ObservedAt, &e.ClassName, &e.ActivityName, &e.Severity,
			&confidence, &e.ActorRef, &e.TargetRef, &e.Action, &e.Outcome, &e.MITRE, &e.Vendor, &e.Product,
			&e.RawPointer, &e.Checksum, &data); err != nil {
			return nil, err
		}
		e.Confidence = int(confidence)
		_ = json.Unmarshal([]byte(data), &e.Data)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Query returns matching events for the tenant, newest first. The tenant_id
// predicate is mandatory and always applied first (isolation, ADR-0002).
func (s *ClickHouseStore) Query(ctx context.Context, tenantID uuid.UUID, q Query) ([]NormalizedEvent, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	sql := `SELECT id, tenant_id, schema_version, dedupe_key, source, connector_id, collected_at, observed_at,
	               class_name, activity_name, severity, confidence,
	               actor_ref, target_ref, action, outcome, mitre, vendor, product, raw_pointer, checksum, data
	          FROM events WHERE tenant_id = ?`
	args := []any{tenantID}
	if !q.From.IsZero() {
		sql += " AND observed_at >= ?"
		args = append(args, q.From)
	}
	if !q.To.IsZero() {
		sql += " AND observed_at <= ?"
		args = append(args, q.To)
	}
	if q.Severity != "" {
		sql += " AND severity = ?"
		args = append(args, q.Severity)
	}
	if q.Search != "" {
		sql += " AND (class_name ILIKE ? OR action ILIKE ? OR actor_ref ILIKE ? OR target_ref ILIKE ?)"
		like := "%" + q.Search + "%"
		args = append(args, like, like, like, like)
	}
	sql += " ORDER BY observed_at DESC LIMIT ?"
	args = append(args, q.Limit)

	rows, err := s.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NormalizedEvent
	for rows.Next() {
		var e NormalizedEvent
		var data string
		var confidence int32
		if err := rows.Scan(&e.ID, &e.TenantID, &e.SchemaVersion, &e.DedupeKey, &e.Source, &e.ConnectorID,
			&e.CollectedAt, &e.ObservedAt, &e.ClassName, &e.ActivityName, &e.Severity,
			&confidence, &e.ActorRef, &e.TargetRef, &e.Action, &e.Outcome, &e.MITRE, &e.Vendor, &e.Product,
			&e.RawPointer, &e.Checksum, &data); err != nil {
			return nil, err
		}
		e.Confidence = int(confidence)
		_ = json.Unmarshal([]byte(data), &e.Data)
		out = append(out, e)
	}
	return out, rows.Err()
}
