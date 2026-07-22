package recovery

import (
	"errors"
	"testing"
	"time"
)

func passingAssertions() []Assertion {
	return []Assertion{
		{Dimension: DimensionIntegrity, Passed: true, Evidence: "row counts and checksums reconciled"},
		{Dimension: DimensionCrypto, Passed: true, Evidence: "all encrypted-domain probes decrypted"},
		{Dimension: DimensionSecurity, Passed: true, Evidence: "RLS and security fences passed"},
		{Dimension: DimensionTenantIsolation, Passed: true, Evidence: "two-tenant non-contamination proof passed"},
		{Dimension: DimensionAudit, Passed: true, Evidence: "audit seam and append-only checks passed"},
		{Dimension: DimensionStaleness, Passed: true, Evidence: "stale-state and replay checks passed"},
		{Dimension: DimensionConfig, Passed: true, Evidence: "required secrets and deploy posture passed"},
		{Dimension: DimensionFunctional, Passed: true, Evidence: "canonical restored-stack journey passed"},
	}
}

func TestCertifyRequiresEveryDimension(t *testing.T) {
	assertions := passingAssertions()
	assertions = assertions[:len(assertions)-1]
	certification, err := Certify("restore-1", "backup-1", time.Now(), assertions)
	if !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("missing dimension must fail closed, got %v", err)
	}
	if certification.Certified {
		t.Fatal("partial validation was certified")
	}
}

func TestCertifyAnyFailureFailsWholeRecovery(t *testing.T) {
	assertions := passingAssertions()
	assertions[3].Passed = false
	certification, err := Certify("restore-1", "backup-1", time.Now(), assertions)
	if !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("failed tenant-isolation assertion must refuse certification, got %v", err)
	}
	if certification.Certified {
		t.Fatal("failed recovery dimension was certified")
	}
}

func TestCertifyRequiresEvidence(t *testing.T) {
	assertions := passingAssertions()
	assertions[1].Evidence = "   "
	_, err := Certify("restore-1", "backup-1", time.Now(), assertions)
	if !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("evidence-free assertion must fail closed, got %v", err)
	}
}

func TestServingGateRefusesUncertifiedRestore(t *testing.T) {
	if err := RequireServingCertification(true, nil); !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("nil certification must refuse restored serving, got %v", err)
	}
	forged := &Certification{RestoreID: "restore-1", BackupID: "backup-1", ValidatedAt: time.Now(), Certified: true}
	if err := RequireServingCertification(true, forged); !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("boolean-only forged certification bypassed serving gate: %v", err)
	}
}

func TestServingGateAllowsOnlyCompleteCertifiedRestore(t *testing.T) {
	certification, err := Certify("restore-1", "backup-1", time.Now(), passingAssertions())
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireServingCertification(true, &certification); err != nil {
		t.Fatalf("complete certification should allow restored serving: %v", err)
	}
	if err := RequireServingCertification(false, nil); err != nil {
		t.Fatalf("ordinary non-restored startup should be unaffected: %v", err)
	}
}

func TestServingGateDetectsPostCertificationMutation(t *testing.T) {
	certification, err := Certify("restore-1", "backup-1", time.Now(), passingAssertions())
	if err != nil {
		t.Fatal(err)
	}
	certification.Assertions[0].Passed = false
	if err := RequireServingCertification(true, &certification); !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("mutated certification must be refused, got %v", err)
	}
}
