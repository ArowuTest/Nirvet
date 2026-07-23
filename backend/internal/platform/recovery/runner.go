package recovery

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Validator proves one recovery dimension and returns reviewer-verifiable evidence.
// Validators must inspect the restored stack; an empty evidence string is a failure.
type Validator interface {
	ValidateRecovery(ctx context.Context) (string, error)
}

// ValidatorFunc adapts a function into a Validator.
type ValidatorFunc func(context.Context) (string, error)

func (f ValidatorFunc) ValidateRecovery(ctx context.Context) (string, error) {
	return f(ctx)
}

// ValidationPlan is the complete, non-optional recovery assertion set. Keeping
// every dimension as an explicit field prevents a caller from silently omitting a
// slow or inconvenient check and still obtaining a certification.
type ValidationPlan struct {
	Integrity       Validator
	Crypto          Validator
	Security        Validator
	TenantIsolation Validator
	Audit           Validator
	Staleness       Validator
	Config          Validator
	Functional      Validator
}

// RunValidation executes all dimensions in a fixed order and certifies only when
// every validator ran, passed, and returned evidence. It stops at the first
// failure so no uncertified restore can be mistaken for a partial success.
func RunValidation(ctx context.Context, restoreID, backupID string, at time.Time, plan ValidationPlan) (Certification, error) {
	checks := []struct {
		dimension Dimension
		validator Validator
	}{
		{DimensionIntegrity, plan.Integrity},
		{DimensionCrypto, plan.Crypto},
		{DimensionSecurity, plan.Security},
		{DimensionTenantIsolation, plan.TenantIsolation},
		{DimensionAudit, plan.Audit},
		{DimensionStaleness, plan.Staleness},
		{DimensionConfig, plan.Config},
		{DimensionFunctional, plan.Functional},
	}

	assertions := make([]Assertion, 0, len(checks))
	for _, check := range checks {
		if check.validator == nil {
			return Certification{}, fmt.Errorf("%w: validator %q is not configured", ErrUncertifiedRestore, check.dimension)
		}
		evidence, err := check.validator.ValidateRecovery(ctx)
		if err != nil {
			return Certification{}, fmt.Errorf("%w: dimension %q: %v", ErrUncertifiedRestore, check.dimension, err)
		}
		if strings.TrimSpace(evidence) == "" {
			return Certification{}, fmt.Errorf("%w: dimension %q returned no evidence", ErrUncertifiedRestore, check.dimension)
		}
		assertions = append(assertions, Assertion{Dimension: check.dimension, Passed: true, Evidence: evidence})
	}

	return Certify(restoreID, backupID, at, assertions)
}
