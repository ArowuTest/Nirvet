package compliance

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Service assesses tenant compliance against configured frameworks.
type Service struct{ repo *Repository }

// NewService builds the service.
func NewService(repo *Repository) *Service { return &Service{repo: repo} }

// ControlAssessment is the assessed status of a single control.
type ControlAssessment struct {
	ControlRef  string `json:"control_ref"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	Score       int    `json:"score"`
	Source      string `json:"source"` // auto | manual
	Note        string `json:"note"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// FunctionAssessment is a top-level control (e.g. a NIST CSF function) with its children rolled up.
type FunctionAssessment struct {
	ControlRef string              `json:"control_ref"`
	Title      string              `json:"title"`
	Status     string              `json:"status"`
	Score      int                 `json:"score"`
	Controls   []ControlAssessment `json:"controls"`
}

// Coverage is the full framework assessment for a tenant.
type Coverage struct {
	Framework string               `json:"framework"`
	Score     int                  `json:"score"`
	Summary   map[string]int       `json:"summary"`
	Functions []FunctionAssessment `json:"functions"`
}

// ListFrameworks returns the frameworks visible to the tenant.
func (s *Service) ListFrameworks(ctx context.Context, tenantID uuid.UUID) ([]Framework, error) {
	return s.repo.ListFrameworks(ctx, tenantID)
}

// ListControls returns the controls of a framework.
func (s *Service) ListControls(ctx context.Context, tenantID uuid.UUID, frameworkKey string) ([]Control, error) {
	return s.repo.ListControls(ctx, tenantID, frameworkKey)
}

// Assess evaluates every control of a framework for the tenant: a manual override wins; otherwise the
// control's mapped signal resolver measures live state; a top-level function rolls up its children.
func (s *Service) Assess(ctx context.Context, tenantID uuid.UUID, frameworkKey string) (*Coverage, error) {
	controls, err := s.repo.ListControls(ctx, tenantID, frameworkKey)
	if err != nil {
		return nil, httpx.ErrInternal("could not load controls")
	}
	if len(controls) == 0 {
		return nil, httpx.ErrNotFound("unknown or empty framework")
	}
	manual, err := s.repo.ManualStatuses(ctx, tenantID, frameworkKey)
	if err != nil {
		return nil, httpx.ErrInternal("could not load control status")
	}

	// Leaves (parent_ref != "") assessed first; grouped under their parent function.
	leavesByParent := map[string][]ControlAssessment{}
	var functions []Control
	parentRefOf := map[string]string{} // controlRef -> its own parent_ref (for the depth guard)
	for _, c := range controls {
		parentRefOf[c.ControlRef] = c.ParentRef
	}
	for _, c := range controls {
		if c.ParentRef == "" {
			functions = append(functions, c)
			continue
		}
		ca := assessLeaf(ctx, s.repo, tenantID, c, manual)
		leavesByParent[c.ParentRef] = append(leavesByParent[c.ParentRef], ca)
	}
	// Depth guard (carry-forward Low): the rollup is two-level (function → leaf children). A control
	// whose parent is ITSELF a child (3+ levels) would be assessed as a leaf while its own children —
	// keyed under it in leavesByParent — are never rolled up (that key is not a top-level function),
	// silently dropping them from the score. Current seeds are ≤2 levels; fail LOUD before a deeper
	// catalogue is loaded rather than emit a silently-wrong posture (compliance never fabricates).
	for parent := range leavesByParent {
		if parentRefOf[parent] != "" {
			return nil, httpx.ErrInternal("framework has >2-level control nesting, which the rollup does not yet support")
		}
	}

	cov := &Coverage{Framework: frameworkKey, Summary: map[string]int{}}
	var totalScore, totalWeight int
	// Weight map for functions' children roll-up (weight lives on the control row).
	weightOf := map[string]int{}
	for _, c := range controls {
		weightOf[c.ControlRef] = c.Weight
	}

	tally := func(ref, status string, score int) {
		cov.Summary[status]++
		if status == StatusNotApplicable {
			return
		}
		w := weightOf[ref]
		if w <= 0 {
			w = 1
		}
		totalScore += score * w
		totalWeight += w
	}

	for _, fn := range functions {
		kids := leavesByParent[fn.ControlRef]
		fa := FunctionAssessment{ControlRef: fn.ControlRef, Title: fn.Title, Controls: kids}
		if len(kids) > 0 {
			// A top-level control WITH children is a rollup: status derives from the children (a manual
			// override on the parent is display-only), and the CHILDREN are the tallied units (NIST CSF).
			if m, ok := manual[fn.ControlRef]; ok {
				fa.Status, fa.Score = m.Status, m.Score
			} else {
				fa.Score, fa.Status = rollup(kids, weightOf)
			}
			for _, ca := range kids {
				tally(ca.ControlRef, ca.Status, ca.Score)
			}
		} else {
			// R6-C3: a CHILDLESS top-level control (flat-seeded CIS v8.1 / ISO 27001) is an assessed leaf
			// in its own right — resolve its signal / manual override and tally it, so the framework does
			// not score 0/not_applicable. This also makes a manual override on such a control count.
			ca := assessLeaf(ctx, s.repo, tenantID, fn, manual)
			fa.Status, fa.Score = ca.Status, ca.Score
			tally(fn.ControlRef, ca.Status, ca.Score)
		}
		cov.Functions = append(cov.Functions, fa)
	}
	if totalWeight > 0 {
		cov.Score = totalScore / totalWeight
	}
	return cov, nil
}

// SetStatusInput is a manual control-status override (COMP-004).
type SetStatusInput struct {
	FrameworkKey string `json:"framework_key"`
	ControlRef   string `json:"control_ref"`
	Status       string `json:"status"`
	Note         string `json:"note"`
	EvidenceRef  string `json:"evidence_ref"`
}

// SetControlStatus records a manual assessment for a control (audited via the mutation middleware).
func (s *Service) SetControlStatus(ctx context.Context, tenantID uuid.UUID, in SetStatusInput, actor uuid.UUID) error {
	if in.FrameworkKey == "" || in.ControlRef == "" {
		return httpx.ErrBadRequest("framework_key and control_ref are required")
	}
	if !validStatus(in.Status) {
		return httpx.ErrBadRequest("status must be met|partial|gap|not_applicable")
	}
	// The control must exist in the framework (global or tenant) — no free-floating status rows.
	controls, err := s.repo.ListControls(ctx, tenantID, in.FrameworkKey)
	if err != nil {
		return httpx.ErrInternal("could not verify control")
	}
	if !controlExists(controls, in.ControlRef) {
		return httpx.ErrNotFound("control not found in framework")
	}
	st := ControlStatus{
		FrameworkKey: in.FrameworkKey, ControlRef: in.ControlRef, Status: in.Status,
		Score: scoreOf(in.Status), Note: in.Note, EvidenceRef: in.EvidenceRef,
	}
	if err := s.repo.UpsertManualStatus(ctx, tenantID, st, actor); err != nil {
		return httpx.ErrInternal("could not save status")
	}
	return nil
}

func assessLeaf(ctx context.Context, r *Repository, tenantID uuid.UUID, c Control, manual map[string]ControlStatus) ControlAssessment {
	if m, ok := manual[c.ControlRef]; ok {
		return ControlAssessment{ControlRef: c.ControlRef, Title: c.Title, Status: m.Status,
			Score: m.Score, Source: "manual", Note: m.Note, EvidenceRef: m.EvidenceRef}
	}
	sig := resolveSignal(ctx, r, tenantID, c)
	return ControlAssessment{ControlRef: c.ControlRef, Title: c.Title, Status: sig.Status,
		Score: scoreOf(sig.Status), Source: "auto", Note: sig.Note}
}

// rollup computes a weighted function score + status from its children.
func rollup(kids []ControlAssessment, weightOf map[string]int) (int, string) {
	var sum, wt int
	for _, k := range kids {
		if k.Status == StatusNotApplicable {
			continue
		}
		w := weightOf[k.ControlRef]
		if w <= 0 {
			w = 1
		}
		sum += k.Score * w
		wt += w
	}
	if wt == 0 {
		return 0, StatusNotApplicable
	}
	score := sum / wt
	switch {
	case score >= 67:
		return score, StatusMet
	case score > 0:
		return score, StatusPartial
	default:
		return score, StatusGap
	}
}

func validStatus(s string) bool {
	switch s {
	case StatusMet, StatusPartial, StatusGap, StatusNotApplicable:
		return true
	}
	return false
}

func controlExists(controls []Control, ref string) bool {
	for _, c := range controls {
		if c.ControlRef == ref {
			return true
		}
	}
	return false
}
