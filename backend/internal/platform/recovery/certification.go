// Package recovery contains the fail-closed certification boundary for restored
// Nirvet instances. A restore is untrusted until every required validation
// dimension has passed; callers must not infer safety from a successful data copy.
package recovery

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var ErrUncertifiedRestore = errors.New("recovery: restored instance is not certified")

// Dimension is one load-bearing recovery assertion from
// build/GATE_FULL_STACK_RECOVERY_VALIDATION.md §3.
type Dimension string

const (
	DimensionIntegrity       Dimension = "data_integrity"
	DimensionCrypto          Dimension = "crypto_continuity"
	DimensionSecurity        Dimension = "security_invariants"
	DimensionTenantIsolation Dimension = "tenant_isolation"
	DimensionAudit           Dimension = "audit_continuity"
	DimensionStaleness       Dimension = "staleness_replay_safety"
	DimensionConfig          Dimension = "config_secret_completeness"
	DimensionFunctional      Dimension = "functional_recovery"
)

var requiredDimensions = []Dimension{
	DimensionIntegrity,
	DimensionCrypto,
	DimensionSecurity,
	DimensionTenantIsolation,
	DimensionAudit,
	DimensionStaleness,
	DimensionConfig,
	DimensionFunctional,
}

// Assertion is the immutable result of one recovery-validation dimension.
type Assertion struct {
	Dimension Dimension `json:"dimension"`
	Passed    bool      `json:"passed"`
	Evidence  string    `json:"evidence"`
}

// Certification is binary: Certified is true only when every required
// dimension appears exactly once and passed. Signature authenticates the
// serialized certification at the restored-serving boundary.
type Certification struct {
	RestoreID   string      `json:"restore_id"`
	BackupID    string      `json:"backup_id"`
	ValidatedAt time.Time   `json:"validated_at"`
	Assertions  []Assertion `json:"assertions"`
	Certified   bool        `json:"certified"`
	Signature   string      `json:"signature,omitempty"`
}

// Certify evaluates a complete set of assertions. Missing, duplicate, unknown,
// failed, or evidence-free dimensions fail closed.
func Certify(restoreID, backupID string, at time.Time, assertions []Assertion) (Certification, error) {
	result := Certification{
		RestoreID:   strings.TrimSpace(restoreID),
		BackupID:    strings.TrimSpace(backupID),
		ValidatedAt: at.UTC(),
		Assertions:  append([]Assertion(nil), assertions...),
	}
	if result.RestoreID == "" || result.BackupID == "" || at.IsZero() {
		return result, fmt.Errorf("%w: restore id, backup id, and validation time are required", ErrUncertifiedRestore)
	}

	required := make(map[Dimension]struct{}, len(requiredDimensions))
	for _, dimension := range requiredDimensions {
		required[dimension] = struct{}{}
	}
	seen := make(map[Dimension]struct{}, len(assertions))
	for _, assertion := range assertions {
		if _, ok := required[assertion.Dimension]; !ok {
			return result, fmt.Errorf("%w: unknown dimension %q", ErrUncertifiedRestore, assertion.Dimension)
		}
		if _, duplicate := seen[assertion.Dimension]; duplicate {
			return result, fmt.Errorf("%w: duplicate dimension %q", ErrUncertifiedRestore, assertion.Dimension)
		}
		seen[assertion.Dimension] = struct{}{}
		if !assertion.Passed {
			return result, fmt.Errorf("%w: dimension %q failed", ErrUncertifiedRestore, assertion.Dimension)
		}
		if strings.TrimSpace(assertion.Evidence) == "" {
			return result, fmt.Errorf("%w: dimension %q has no evidence", ErrUncertifiedRestore, assertion.Dimension)
		}
	}

	var missing []string
	for _, dimension := range requiredDimensions {
		if _, ok := seen[dimension]; !ok {
			missing = append(missing, string(dimension))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return result, fmt.Errorf("%w: missing dimensions: %s", ErrUncertifiedRestore, strings.Join(missing, ", "))
	}

	result.Certified = true
	return result, nil
}

// RequireServingCertification is the serving-path choke point. Restored mode
// requires an explicit, complete certification. Normal non-restored startup is
// unaffected. A nil or malformed certification always refuses serving.
func RequireServingCertification(restoredMode bool, certification *Certification) error {
	if !restoredMode {
		return nil
	}
	if certification == nil || !certification.Certified || certification.RestoreID == "" || certification.BackupID == "" || certification.ValidatedAt.IsZero() {
		return ErrUncertifiedRestore
	}
	if len(certification.Assertions) != len(requiredDimensions) {
		return ErrUncertifiedRestore
	}
	seen := make(map[Dimension]struct{}, len(certification.Assertions))
	for _, assertion := range certification.Assertions {
		if !assertion.Passed || strings.TrimSpace(assertion.Evidence) == "" {
			return ErrUncertifiedRestore
		}
		if _, duplicate := seen[assertion.Dimension]; duplicate {
			return ErrUncertifiedRestore
		}
		seen[assertion.Dimension] = struct{}{}
	}
	for _, dimension := range requiredDimensions {
		if _, ok := seen[dimension]; !ok {
			return ErrUncertifiedRestore
		}
	}
	return nil
}
