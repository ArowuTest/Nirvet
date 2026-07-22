package recovery

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCertification(t *testing.T, certification Certification) string {
	t.Helper()
	data, err := json.Marshal(certification)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "certification.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRequireServingFromEnvBlocksRestoredModeWithoutCertification(t *testing.T) {
	t.Setenv(EnvRestoredMode, "true")
	t.Setenv(EnvCertificationFile, "")
	if err := RequireServingFromEnv(); !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("restored startup without certification must fail closed, got %v", err)
	}
}

func TestRequireServingFromEnvRefusesForgedBooleanOnlyDocument(t *testing.T) {
	forged := Certification{RestoreID: "restore-1", BackupID: "backup-1", ValidatedAt: time.Now(), Certified: true}
	t.Setenv(EnvRestoredMode, "true")
	t.Setenv(EnvCertificationFile, writeCertification(t, forged))
	if err := RequireServingFromEnv(); !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("forged certification bypassed startup gate: %v", err)
	}
}

func TestRequireServingFromEnvAllowsCompleteCertification(t *testing.T) {
	certification, err := Certify("restore-1", "backup-1", time.Now(), passingAssertions())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvRestoredMode, "true")
	t.Setenv(EnvCertificationFile, writeCertification(t, certification))
	if err := RequireServingFromEnv(); err != nil {
		t.Fatalf("complete recovery certification should permit startup: %v", err)
	}
}

func TestRequireServingFromEnvNormalStartupUnaffected(t *testing.T) {
	t.Setenv(EnvRestoredMode, "false")
	t.Setenv(EnvCertificationFile, filepath.Join(t.TempDir(), "missing.json"))
	if err := RequireServingFromEnv(); err != nil {
		t.Fatalf("ordinary startup should not require recovery certification: %v", err)
	}
}

func TestRequireServingFromEnvRejectsInvalidMode(t *testing.T) {
	t.Setenv(EnvRestoredMode, "sometimes")
	if err := RequireServingFromEnv(); err == nil {
		t.Fatal("invalid restored-mode configuration must fail closed")
	}
}
