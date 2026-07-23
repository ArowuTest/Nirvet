package recovery

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func testCertificationKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func setCertificationKey(t *testing.T, key []byte) {
	t.Helper()
	t.Setenv(EnvCertificationKeyBase64, base64.StdEncoding.EncodeToString(key))
}

func encodeCertification(t *testing.T, certification Certification) string {
	t.Helper()
	data, err := json.Marshal(certification)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func TestRequireServingFromEnvBlocksRestoredModeWithoutCertification(t *testing.T) {
	t.Setenv(EnvRestoredMode, "true")
	t.Setenv(EnvCertificationDocumentB64, "")
	setCertificationKey(t, testCertificationKey())
	if err := RequireServingFromEnv(); !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("restored startup without certification must fail closed, got %v", err)
	}
}

func TestRequireServingFromEnvRefusesForgedBooleanOnlyDocument(t *testing.T) {
	forged := Certification{RestoreID: "restore-1", BackupID: "backup-1", ValidatedAt: time.Now(), Certified: true}
	t.Setenv(EnvRestoredMode, "true")
	t.Setenv(EnvCertificationDocumentB64, encodeCertification(t, forged))
	setCertificationKey(t, testCertificationKey())
	if err := RequireServingFromEnv(); !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("forged certification bypassed startup gate: %v", err)
	}
}

func TestRequireServingFromEnvRefusesTamperedCompleteDocument(t *testing.T) {
	key := testCertificationKey()
	certification, err := Certify("restore-1", "backup-1", time.Now(), passingAssertions())
	if err != nil {
		t.Fatal(err)
	}
	certification, err = SignCertification(certification, key)
	if err != nil {
		t.Fatal(err)
	}
	certification.Assertions[0].Evidence = "forged passing evidence"
	t.Setenv(EnvRestoredMode, "true")
	t.Setenv(EnvCertificationDocumentB64, encodeCertification(t, certification))
	setCertificationKey(t, key)
	if err := RequireServingFromEnv(); !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("tampered complete certification bypassed startup gate: %v", err)
	}
}

func TestRequireServingFromEnvAllowsCompleteSignedCertification(t *testing.T) {
	key := testCertificationKey()
	certification, err := Certify("restore-1", "backup-1", time.Now(), passingAssertions())
	if err != nil {
		t.Fatal(err)
	}
	certification, err = SignCertification(certification, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvRestoredMode, "true")
	t.Setenv(EnvCertificationDocumentB64, encodeCertification(t, certification))
	setCertificationKey(t, key)
	if err := RequireServingFromEnv(); err != nil {
		t.Fatalf("complete signed recovery certification should permit startup: %v", err)
	}
}

func TestRequireServingFromEnvMissingSigningKeyFailsClosed(t *testing.T) {
	certification, err := Certify("restore-1", "backup-1", time.Now(), passingAssertions())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvRestoredMode, "true")
	t.Setenv(EnvCertificationDocumentB64, encodeCertification(t, certification))
	t.Setenv(EnvCertificationKeyBase64, "")
	if err := RequireServingFromEnv(); !errors.Is(err, ErrUncertifiedRestore) {
		t.Fatalf("missing certification key did not fail closed: %v", err)
	}
}

func TestRequireServingFromEnvNormalStartupUnaffected(t *testing.T) {
	t.Setenv(EnvRestoredMode, "false")
	t.Setenv(EnvCertificationDocumentB64, "not-base64")
	t.Setenv(EnvCertificationKeyBase64, "")
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
