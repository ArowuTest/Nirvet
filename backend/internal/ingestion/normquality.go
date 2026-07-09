package ingestion

// §6.5 slice A: normalization data-quality + drift observability (NORM-003/009) and its per-tenant
// config (NORM-006). Quality is accumulated in memory per normalized event and flushed to
// normalization_quality once per worker batch — never a per-event DB write.

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// NormSettings are per-tenant normalization tuning knobs (lazy default).
type NormSettings struct {
	MinConfidence int `json:"min_confidence"` // avg confidence below this over the window = drift
	WindowDays    int `json:"window_days"`
}

// DefaultNormSettings is returned when a tenant has no normalization_settings row.
func DefaultNormSettings() NormSettings { return NormSettings{MinConfidence: 50, WindowDays: 7} }

// SourceQuality is the per-source normalization health reported by the dashboard.
type SourceQuality struct {
	Source        string `json:"source"`
	Events        int64  `json:"events"`
	AvgConfidence int    `json:"avg_confidence"`
	Parser        string `json:"parser"`
	ParserVersion int    `json:"parser_version"`
	Drift         bool   `json:"drift"` // avg_confidence < tenant min_confidence
}

type qKey struct {
	tenant uuid.UUID
	source string
	day    int
}
type qDelta struct {
	events, sumConf int64
	parser          string
	parserVersion   int
}

// NormQuality accumulates normalization quality in memory and flushes it in batches.
type NormQuality struct {
	db  *database.DB
	mu  sync.Mutex
	agg map[qKey]*qDelta
}

// NewNormQuality builds the recorder.
func NewNormQuality(db *database.DB) *NormQuality {
	return &NormQuality{db: db, agg: map[qKey]*qDelta{}}
}

// Record accumulates one normalized event's quality in memory (no DB write). Safe for concurrent use.
func (n *NormQuality) Record(tenantID uuid.UUID, source, parser string, parserVersion, confidence int) {
	if source == "" {
		return
	}
	k := qKey{tenant: tenantID, source: strings.ToLower(source), day: time.Now().YearDay()}
	n.mu.Lock()
	d := n.agg[k]
	if d == nil {
		d = &qDelta{}
		n.agg[k] = d
	}
	d.events++
	d.sumConf += int64(confidence)
	d.parser = parser
	d.parserVersion = parserVersion
	n.mu.Unlock()
}

// Flush upserts the accumulated deltas and clears them. Best-effort; called once per worker batch. On a
// per-key failure the delta is merged back so counts are not lost (they flush on the next batch).
func (n *NormQuality) Flush(ctx context.Context) error {
	n.mu.Lock()
	if len(n.agg) == 0 {
		n.mu.Unlock()
		return nil
	}
	pending := n.agg
	n.agg = map[qKey]*qDelta{}
	n.mu.Unlock()

	var firstErr error
	for k, d := range pending {
		err := n.db.WithTenant(ctx, k.tenant, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx,
				`INSERT INTO normalization_quality (tenant_id, source, day, events, sum_confidence, parser, parser_version, updated_at)
				 VALUES ($1,$2,$3,$4,$5,$6,$7, now())
				 ON CONFLICT (tenant_id, source, day) DO UPDATE SET
				   events = normalization_quality.events + EXCLUDED.events,
				   sum_confidence = normalization_quality.sum_confidence + EXCLUDED.sum_confidence,
				   parser = EXCLUDED.parser, parser_version = EXCLUDED.parser_version, updated_at = now()`,
				k.tenant, k.source, k.day, d.events, d.sumConf, d.parser, d.parserVersion)
			return e
		})
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			n.mu.Lock() // merge the failed delta back
			if cur := n.agg[k]; cur != nil {
				cur.events += d.events
				cur.sumConf += d.sumConf
			} else {
				n.agg[k] = d
			}
			n.mu.Unlock()
		}
	}
	return firstErr
}

// GetSettings returns the tenant's normalization settings, or defaults when unset.
func (n *NormQuality) GetSettings(ctx context.Context, tenantID uuid.UUID) (NormSettings, error) {
	s := DefaultNormSettings()
	err := n.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT min_confidence, window_days FROM normalization_settings WHERE tenant_id=$1`, tenantID).
			Scan(&s.MinConfidence, &s.WindowDays)
		if e == pgx.ErrNoRows {
			return nil
		}
		return e
	})
	return s, err
}

// SetSettings validates and upserts the tenant's normalization settings.
func (n *NormQuality) SetSettings(ctx context.Context, tenantID uuid.UUID, in NormSettings) (NormSettings, error) {
	if in.MinConfidence < 0 || in.MinConfidence > 100 {
		return NormSettings{}, httpx.ErrBadRequest("min_confidence must be between 0 and 100")
	}
	if in.WindowDays < 1 || in.WindowDays > 90 {
		return NormSettings{}, httpx.ErrBadRequest("window_days must be between 1 and 90")
	}
	err := n.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO normalization_settings (tenant_id, min_confidence, window_days, updated_at)
			 VALUES ($1,$2,$3, now())
			 ON CONFLICT (tenant_id) DO UPDATE SET min_confidence=$2, window_days=$3, updated_at=now()`,
			tenantID, in.MinConfidence, in.WindowDays)
		return e
	})
	if err != nil {
		return NormSettings{}, httpx.ErrInternal("could not save normalization settings")
	}
	return in, nil
}

// Quality returns per-source normalization health over the configured window, with a drift flag when a
// source's average confidence has fallen below the tenant's min_confidence (NORM-003/009).
func (n *NormQuality) Quality(ctx context.Context, tenantID uuid.UUID) ([]SourceQuality, error) {
	set, err := n.GetSettings(ctx, tenantID)
	if err != nil {
		return nil, httpx.ErrInternal("could not load normalization settings")
	}
	var out []SourceQuality
	err = n.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT source, sum(events)::bigint, sum(sum_confidence)::bigint, max(parser), max(parser_version)
			   FROM normalization_quality
			  WHERE updated_at > now() - make_interval(days => $1)
			  GROUP BY source ORDER BY source`, set.WindowDays)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var q SourceQuality
			var events, sumConf int64
			if e := rows.Scan(&q.Source, &events, &sumConf, &q.Parser, &q.ParserVersion); e != nil {
				return e
			}
			q.Events = events
			if events > 0 {
				q.AvgConfidence = int(sumConf / events)
			}
			q.Drift = events > 0 && q.AvgConfidence < set.MinConfidence
			out = append(out, q)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not load normalization quality")
	}
	return out, nil
}
