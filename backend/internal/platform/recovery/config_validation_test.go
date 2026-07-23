package recovery

import (
	"strings"
	"testing"
)

func TestValidateConfigCompletenessPassesWithoutLeakingValues(t *testing.T) {
	requirements := []ConfigRequirement{
		{Name: "NIRVET_DATABASE_URL", Sensitive: true},
		{Name: "NIRVET_JWT_SECRET", Sensitive: true},
		{Name: "NIRVET_CRYPTO_PROVIDER"},
	}
	values := make(map[string]string)
	values["NIRVET_DATABASE_URL"] = "postgres://secret-value"
	values["NIRVET_JWT_SECRET"] = "top-secret-marker"
	values["NIRVET_CRYPTO_PROVIDER"] = "vault"
	evidence, err := ValidateConfigCompleteness(requirements, values)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(evidence, "secret-value") || strings.Contains(evidence, "top-secret-marker") {
		t.Fatal("recovery evidence leaked secret configuration values")
	}
}

func TestValidateConfigCompletenessMissingSecretFailsClosed(t *testing.T) {
	requirements := []ConfigRequirement{{Name: "NIRVET_DATABASE_URL", Sensitive: true}, {Name: "NIRVET_JWT_SECRET", Sensitive: true}}
	_, err := ValidateConfigCompleteness(requirements, map[string]string{"NIRVET_DATABASE_URL": "postgres://present"})
	if err == nil || !strings.Contains(err.Error(), "NIRVET_JWT_SECRET") {
		t.Fatalf("missing restored secret did not fail closed: %v", err)
	}
}

func TestValidateConfigCompletenessRejectsEmptyInventory(t *testing.T) {
	if _, err := ValidateConfigCompleteness(nil, nil); err == nil {
		t.Fatal("empty deployment config inventory was treated as complete")
	}
}

func TestValidateConfigCompletenessRejectsDuplicateRequirement(t *testing.T) {
	requirements := []ConfigRequirement{{Name: "NIRVET_DATABASE_URL"}, {Name: "NIRVET_DATABASE_URL"}}
	if _, err := ValidateConfigCompleteness(requirements, map[string]string{"NIRVET_DATABASE_URL": "present"}); err == nil {
		t.Fatal("duplicate config requirement was accepted")
	}
}
