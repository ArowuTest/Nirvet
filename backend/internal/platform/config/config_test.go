package config

import (
	"strings"
	"testing"
)

// TestLoadDevelopmentDefaults: with nothing set, the platform loads with safe local
// defaults (development). None of the production guards fire.
func TestLoadDevelopmentDefaults(t *testing.T) {
	// Ensure a clean production-related environment.
	for _, k := range []string{"NIRVET_ENV", "NIRVET_JWT_SECRET", "NIRVET_BOOTSTRAP_PASSWORD", "NIRVET_SECRET_MASTER_KEY", "NIRVET_KMS_KEY_NAME"} {
		t.Setenv(k, "")
	}
	c, err := Load()
	if err != nil {
		t.Fatalf("development config should load: %v", err)
	}
	if c.IsProduction() {
		t.Fatal("default env must not be production")
	}
}

// TestProductionGuards locks the three fail-fast startup guards: a production
// deployment must not boot on the dev JWT secret, the default bootstrap password, or
// without persistent vault key material.
func TestProductionGuards(t *testing.T) {
	// A fully-valid production environment (mutated per case below).
	base := map[string]string{
		"NIRVET_ENV":                "production",
		"NIRVET_JWT_SECRET":         "a-real-secret",
		"NIRVET_BOOTSTRAP_PASSWORD": "a-real-bootstrap-pw",
		"NIRVET_SECRET_MASTER_KEY":  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32 bytes b64
		"NIRVET_KMS_KEY_NAME":       "",
	}

	cases := []struct {
		name    string
		mutate  map[string]string
		wantErr string // substring; empty => expect success
	}{
		{"all set", nil, ""},
		{"default jwt", map[string]string{"NIRVET_JWT_SECRET": "dev-insecure-change-me"}, "NIRVET_JWT_SECRET"},
		{"default bootstrap pw", map[string]string{"NIRVET_BOOTSTRAP_PASSWORD": "ChangeMe123!"}, "NIRVET_BOOTSTRAP_PASSWORD"},
		{"no vault key", map[string]string{"NIRVET_SECRET_MASTER_KEY": ""}, "NIRVET_SECRET_MASTER_KEY"},
		{"kms satisfies vault", map[string]string{"NIRVET_SECRET_MASTER_KEY": "", "NIRVET_KMS_KEY_NAME": "projects/p/locations/l/keyRings/r/cryptoKeys/k"}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range base {
				t.Setenv(k, v)
			}
			for k, v := range tc.mutate {
				t.Setenv(k, v)
			}
			_, err := Load()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error mentioning %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q should mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}
