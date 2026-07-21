package contentlifecycle

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func testPublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	raw, err := os.ReadFile("testdata/test-publisher.public.hex")
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.PublicKey(b)
}

func verifier(t *testing.T) Verifier {
	t.Helper()
	return Verifier{
		Publishers: map[string]ed25519.PublicKey{"test-publisher": testPublicKey(t)},
		Validators: map[string]ArtifactValidator{
			"detection_rules": ArtifactValidatorFunc(func(_ Manifest, artifact Artifact) error {
				var rule map[string]any
				if err := json.Unmarshal(artifact.Data, &rule); err != nil {
					return err
				}
				expression, _ := rule["expression"].(string)
				if expression == "" {
					return errors.New("missing expression")
				}
				for _, forbidden := range []string{"raw_sql", "soar_action", "exec("} {
					if strings.Contains(strings.ToLower(expression), forbidden) {
						return errors.New("forbidden expression")
					}
				}
				return nil
			}),
		},
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyThenParse_ValidSignedPack(t *testing.T) {
	pack, err := verifier(t).VerifyAndParse(fixture(t, "valid-pack.json"), time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("verify valid fixture: %v", err)
	}
	if pack.Manifest.Version != 1 || len(pack.Artifacts) != 1 {
		t.Fatalf("unexpected pack: %+v", pack)
	}
}

func TestVerifyThenParse_CommittedNegativeFixtures(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		want error
	}{
		{"tampered-pack.json", ErrInvalidSignature},
		{"unsigned-pack.json", ErrMalformedEnvelope},
		{"untrusted-publisher-pack.json", ErrUnknownPublisher},
		{"expired-pack.json", ErrExpired},
		{"malformed-pack.json", ErrMalformedContent},
		{"unsafe-rule-pack.json", ErrSemanticValidation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pack, err := verifier(t).VerifyAndParse(fixture(t, tc.name), now)
			if pack != nil {
				t.Fatalf("partial pack returned for %s", tc.name)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestVerifyThenParse_DowngradeAndCrossTenantFixturesAreSignedAndTraceable(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	downgrade, err := verifier(t).VerifyAndParse(fixture(t, "downgrade-pack.json"), now)
	if err != nil || downgrade.Manifest.Version != 1 {
		t.Fatalf("downgrade fixture not independently verifiable: pack=%+v err=%v", downgrade, err)
	}
	crossTenant, err := verifier(t).VerifyAndParse(fixture(t, "cross-tenant-pack.json"), now)
	if err != nil {
		t.Fatalf("cross-tenant fixture not independently verifiable: %v", err)
	}
	if crossTenant.Manifest.Scope != "tenant" || crossTenant.Manifest.TenantID != "tenant-a" {
		t.Fatalf("unexpected tenant provenance: %+v", crossTenant.Manifest)
	}
}

func TestVerifyThenParse_AtomicSemanticFailure(t *testing.T) {
	v := verifier(t)
	v.Validators["detection_rules"] = ArtifactValidatorFunc(func(_ Manifest, _ Artifact) error {
		return errors.New("manual-authoring validator refused rule")
	})
	pack, err := v.VerifyAndParse(fixture(t, "valid-pack.json"), time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	if pack != nil {
		t.Fatal("partial pack returned on semantic failure")
	}
	if !errors.Is(err, ErrSemanticValidation) {
		t.Fatalf("want semantic validation failure, got %v", err)
	}
}
