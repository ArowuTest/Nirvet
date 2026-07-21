package contentlifecycle

import (
	"crypto/ed25519"
	"encoding/base64"
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

func validFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/valid-pack.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyThenParse_ValidSignedPack(t *testing.T) {
	pack, err := verifier(t).VerifyAndParse(validFixture(t), time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("verify valid fixture: %v", err)
	}
	if pack.Manifest.Version != 1 || len(pack.Artifacts) != 1 {
		t.Fatalf("unexpected pack: %+v", pack)
	}
}

func TestVerifyThenParse_TamperedContentRejectedBeforeParse(t *testing.T) {
	var env Envelope
	if err := json.Unmarshal(validFixture(t), &env); err != nil {
		t.Fatal(err)
	}
	content, err := base64.StdEncoding.DecodeString(env.ContentB64)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)-2] ^= 1
	env.ContentB64 = base64.StdEncoding.EncodeToString(content)
	raw, _ := json.Marshal(env)
	_, err = verifier(t).VerifyAndParse(raw, time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("want invalid signature, got %v", err)
	}
}

func TestVerifyThenParse_UnsignedRejected(t *testing.T) {
	var env Envelope
	_ = json.Unmarshal(validFixture(t), &env)
	env.SignatureB64 = ""
	raw, _ := json.Marshal(env)
	_, err := verifier(t).VerifyAndParse(raw, time.Now())
	if !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("want malformed envelope, got %v", err)
	}
}

func TestVerifyThenParse_UntrustedPublisherRejected(t *testing.T) {
	var env Envelope
	_ = json.Unmarshal(validFixture(t), &env)
	env.PublisherID = "unknown"
	raw, _ := json.Marshal(env)
	_, err := verifier(t).VerifyAndParse(raw, time.Now())
	if !errors.Is(err, ErrUnknownPublisher) {
		t.Fatalf("want unknown publisher, got %v", err)
	}
}

func TestVerifyThenParse_ExpiredRejected(t *testing.T) {
	_, err := verifier(t).VerifyAndParse(validFixture(t), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("want expired, got %v", err)
	}
}

func TestVerifyThenParse_AtomicSemanticFailure(t *testing.T) {
	v := verifier(t)
	v.Validators["detection_rules"] = ArtifactValidatorFunc(func(_ Manifest, _ Artifact) error {
		return errors.New("manual-authoring validator refused rule")
	})
	pack, err := v.VerifyAndParse(validFixture(t), time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	if pack != nil {
		t.Fatal("partial pack returned on semantic failure")
	}
	if !errors.Is(err, ErrSemanticValidation) {
		t.Fatalf("want semantic validation failure, got %v", err)
	}
}
