package investigation

// §6.9 #124 I-5 — the data-gap panel (INV-009: show missing context and data-source gaps to prevent false
// confidence). This is pure UNIFICATION: three real signals already exist and are surfaced separately; the panel
// composes them into one tenant-scoped "what you are NOT seeing" view — detection coverage gaps (a live rule whose
// sources aren't arriving), silent host sources (a source that went quiet), and normalization drift (a source whose
// confidence collapsed). Each underlying reader is tenant-scoped, so the panel can only ever show the caller's tenant.

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/connector"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

// silenceThreshold is how long a host source may be quiet before it shows on the panel (mirrors the US-032 sweeper
// default). A display threshold, not a security control.
const silenceThreshold = 30 * time.Minute

// Narrow read deps (satisfied by detection.Service, *ingestion.NormQuality, *connector.Repository).
type CoverageGapper interface {
	CoverageGaps(ctx context.Context, tenantID uuid.UUID) ([]detection.CoverageGap, error)
}
type DriftReader interface {
	Quality(ctx context.Context, tenantID uuid.UUID) ([]ingestion.SourceQuality, error)
}
type SilenceReader interface {
	TenantSilentHostSources(ctx context.Context, tenantID uuid.UUID, within time.Duration) ([]connector.SilentSource, error)
}

// DataGapService unifies the three data-gap signals.
type DataGapService struct {
	coverage CoverageGapper
	drift    DriftReader
	silence  SilenceReader
}

// NewDataGapService builds the service.
func NewDataGapService(c CoverageGapper, d DriftReader, s SilenceReader) *DataGapService {
	return &DataGapService{coverage: c, drift: d, silence: s}
}

// DataGaps is the unified panel.
type DataGaps struct {
	CoverageGaps    []detection.CoverageGap   `json:"coverage_gaps"`    // live rules starved of their source
	SilentSources   []connector.SilentSource  `json:"silent_sources"`   // host sources that went quiet
	DriftingSources []ingestion.SourceQuality `json:"drifting_sources"` // sources whose confidence collapsed
}

// Get composes the panel for the caller's tenant. Each signal is best-effort — one reader failing yields an empty
// list for that signal rather than failing the whole panel (a partial gap view still beats none).
func (s *DataGapService) Get(ctx context.Context, p auth.Principal) DataGaps {
	var out DataGaps
	if gaps, err := s.coverage.CoverageGaps(ctx, p.TenantID); err == nil {
		out.CoverageGaps = gaps
	}
	if silent, err := s.silence.TenantSilentHostSources(ctx, p.TenantID, silenceThreshold); err == nil {
		out.SilentSources = silent
	}
	if q, err := s.drift.Quality(ctx, p.TenantID); err == nil {
		for _, sq := range q {
			if sq.Drift {
				out.DriftingSources = append(out.DriftingSources, sq)
			}
		}
	}
	return out
}
