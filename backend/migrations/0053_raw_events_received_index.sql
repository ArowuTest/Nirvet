-- Round-6 P1: the ingest quota check counted raw_events per event over received_at, but the only
-- received_at index was PARTIAL (WHERE enqueued_at IS NULL) — useless once rows are enqueued, so every
-- late-day event full-scanned the fastest-growing table (O(N²)/day → ingest collapse). A non-partial
-- (tenant_id, received_at) index makes the daily-count scan an index range; the service also caches the
-- count per tenant with a short TTL so it no longer runs the count per event.
CREATE INDEX IF NOT EXISTS raw_events_tenant_received ON raw_events (tenant_id, received_at);
