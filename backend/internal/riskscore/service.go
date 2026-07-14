package riskscore

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/compliance"
	"github.com/ArowuTest/nirvet/internal/reporting"
	"github.com/ArowuTest/nirvet/internal/vulnerability"
	"github.com/google/uuid"
)

// ExposureReader is the vulnerability-exposure signal (satisfied by vulnerability.Service).
type ExposureReader interface {
	ExposureSummary(ctx context.Context, tenantID uuid.UUID) (*vulnerability.Exposure, error)
}

// ComplianceReader is the compliance-coverage signal (satisfied by compliance.Service).
type ComplianceReader interface {
	ListFrameworks(ctx context.Context, tenantID uuid.UUID) ([]compliance.Framework, error)
	Assess(ctx context.Context, tenantID uuid.UUID, frameworkKey string) (*compliance.Coverage, error)
}

// OperationalReader is the incident/SLA-posture signal (satisfied by reporting.Service).
type OperationalReader interface {
	Summary(ctx context.Context, tenantID uuid.UUID) (*reporting.Summary, error)
}

// ConfigResolver reads the tenant's effective config (satisfied by *Store).
type ConfigResolver interface {
	Resolve(ctx context.Context, tenantID uuid.UUID) (Config, error)
}

// Service composes the three real per-tenant signals into a composite score. Each read is best-effort: a signal
// that errors contributes zero to its component rather than failing the whole score (a partial posture is more
// useful than none), and a missing compliance framework EXCLUDES that component (renormalized), never fakes it.
type Service struct {
	exposure    ExposureReader
	compliance  ComplianceReader
	operational OperationalReader
	cfg         ConfigResolver
}

// NewService wires the risk-score service.
func NewService(exposure ExposureReader, compliance ComplianceReader, operational OperationalReader, cfg ConfigResolver) *Service {
	return &Service{exposure: exposure, compliance: compliance, operational: operational, cfg: cfg}
}

// Compute builds the tenant's current composite score from live signals + resolved config.
func (s *Service) Compute(ctx context.Context, tenantID uuid.UUID) (*Score, error) {
	cfg, _ := s.cfg.Resolve(ctx, tenantID) // Resolve returns DefaultConfig on error (fail-safe)

	ex := ExposureInput{BySeverity: map[string]int{}}
	if s.exposure != nil {
		if exp, err := s.exposure.ExposureSummary(ctx, tenantID); err == nil && exp != nil {
			if exp.BySeverity != nil {
				ex.BySeverity = exp.BySeverity
			}
			ex.ExploitedOpen = exp.ExploitedOpen
			ex.PastDue = exp.PastDue
		}
	}

	cp := ComplianceInput{}
	if s.compliance != nil {
		if fws, err := s.compliance.ListFrameworks(ctx, tenantID); err == nil {
			var sum, n float64
			for _, f := range fws {
				if !f.Enabled {
					continue
				}
				// Assess runs live coverage probes; bounded to the tenant's enabled frameworks. Cache as a
				// fast-follow if this becomes a dashboard hot path.
				if cov, err := s.compliance.Assess(ctx, tenantID, f.Key); err == nil && cov != nil {
					sum += float64(cov.Score)
					n++
				}
			}
			if n > 0 {
				cp.Present = true
				cp.AvgCoveragePct = sum / n
			}
		}
	}

	op := OperationalInput{}
	if s.operational != nil {
		if sm, err := s.operational.Summary(ctx, tenantID); err == nil && sm != nil {
			op.OpenIncidents = sm.SLA.OpenIncidents
			op.AckBreaching = sm.SLA.AckBreaching
			op.ResolveBreaching = sm.SLA.ResolveBreaching
			op.ResolvedLate = sm.SLA.ResolvedLate
		}
	}

	score := Compute(cfg, ex, cp, op)
	return &score, nil
}
