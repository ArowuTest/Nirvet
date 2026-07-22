package recovery

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func completeValidationPlan(calls *[]Dimension) ValidationPlan {
	validator := func(d Dimension) Validator {
		return ValidatorFunc(func(context.Context) (string, error) {
			*calls = append(*calls, d)
			return "evidence for " + string(d), nil
		})
	}
	return ValidationPlan{
		Integrity:       validator(DimensionIntegrity),
		Crypto:          validator(DimensionCrypto),
		Security:        validator(DimensionSecurity),
		TenantIsolation: validator(DimensionTenantIsolation),
		Audit:           validator(DimensionAudit),
		Staleness:       validator(DimensionStaleness),
		Config:          validator(DimensionConfig),
		Functional:      validator(DimensionFunctional),
	}
}

func TestRunValidationExecutesEveryDimensionAndCertifies(t *testing.T) {
	var calls []Dimension
	certification, err := RunValidation(context.Background(), "restore-1", "backup-1", time.Now(), completeValidationPlan(&calls))
	if err != nil {
		t.Fatal(err)
	}
	if !certification.Certified {
		t.Fatal("complete validation plan was not certified")
	}
	if len(calls) != len(requiredDimensions) {
		t.Fatalf("executed %d validators, want %d", len(calls), len(requiredDimensions))
	}
	for i, dimension := range requiredDimensions {
		if calls[i] != dimension {
			t.Fatalf("validator order[%d]=%q want %q", i, calls[i], dimension)
		}
	}
}

func TestRunValidationMissingValidatorFailsClosed(t *testing.T) {
	var calls []Dimension
	plan := completeValidationPlan(&calls)
	plan.Audit = nil
	certification, err := RunValidation(context.Background(), "restore-1", "backup-1", time.Now(), plan)
	if !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("missing validator must fail closed, got %v", err)
	}
	if certification.Certified {
		t.Fatal("plan with missing audit validator was certified")
	}
}

func TestRunValidationAnyDimensionFailureStopsCertification(t *testing.T) {
	for _, failedDimension := range requiredDimensions {
		t.Run(string(failedDimension), func(t *testing.T) {
			var calls []Dimension
			plan := completeValidationPlan(&calls)
			failure := ValidatorFunc(func(context.Context) (string, error) {
				return "", fmt.Errorf("deliberate corruption")
			})
			switch failedDimension {
			case DimensionIntegrity:
				plan.Integrity = failure
			case DimensionCrypto:
				plan.Crypto = failure
			case DimensionSecurity:
				plan.Security = failure
			case DimensionTenantIsolation:
				plan.TenantIsolation = failure
			case DimensionAudit:
				plan.Audit = failure
			case DimensionStaleness:
				plan.Staleness = failure
			case DimensionConfig:
				plan.Config = failure
			case DimensionFunctional:
				plan.Functional = failure
			}
			certification, err := RunValidation(context.Background(), "restore-1", "backup-1", time.Now(), plan)
			if !errors.Is(err, ErrUncertifiedRestore) {
				t.Fatalf("failed %s validator must fail closed, got %v", failedDimension, err)
			}
			if certification.Certified {
				t.Fatalf("failed %s validator was certified", failedDimension)
			}
		})
	}
}

func TestRunValidationEvidenceFreeResultFailsClosed(t *testing.T) {
	var calls []Dimension
	plan := completeValidationPlan(&calls)
	plan.Config = ValidatorFunc(func(context.Context) (string, error) { return "   ", nil })
	_, err := RunValidation(context.Background(), "restore-1", "backup-1", time.Now(), plan)
	if !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("evidence-free validator must fail closed, got %v", err)
	}
}
