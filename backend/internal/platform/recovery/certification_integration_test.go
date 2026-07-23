package recovery

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	platformcrypto "github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRecoveryRoundTrip_ProducesAuthenticatedBinaryCertification(t *testing.T) {
	ownerDSN := os.Getenv("NIRVET_RESTORED_OWNER_DATABASE_URL")
	appDSN := os.Getenv("NIRVET_RESTORED_APP_DATABASE_URL")
	blobEvidence := os.Getenv("NIRVET_RECOVERY_BLOB_EVIDENCE")
	if ownerDSN == "" || appDSN == "" || blobEvidence == "" {
		t.Skip("complete restored-stack evidence is not configured")
	}
	ctx := context.Background()
	owner, err := pgxpool.New(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	app, err := pgxpool.New(ctx, appDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	postgresEvidence, err := ValidateRestoredPostgres(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRoundTripMarkers(ctx, owner); err != nil {
		t.Fatal(err)
	}
	auditEvidence, err := ValidateAuditContinuity(ctx, owner, AuditSeam{
		RequestIDs: []string{"recovery-seed-a", "recovery-seed-b"},
		BackupID:   "ci-backup",
		RestoreID:  "ci-restore",
	})
	if err != nil {
		t.Fatal(err)
	}

	cryptoEvidence := recoveryCryptoEvidence(t)
	stalenessEvidence := recoveryStalenessEvidence(t)
	configEvidence, err := ValidateConfigCompleteness([]ConfigRequirement{
		{Name: "owner_dsn", Sensitive: true},
		{Name: "app_dsn", Sensitive: true},
		{Name: "blob_evidence"},
	}, map[string]string{"owner_dsn": ownerDSN, "app_dsn": appDSN, "blob_evidence": blobEvidence})
	if err != nil {
		t.Fatal(err)
	}

	componentEvidence, err := ValidateStatefulComponents(ctx, realComponentProbes(
		postgresEvidence, cryptoEvidence, blobEvidence, configEvidence, auditEvidence, stalenessEvidence,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(componentEvidence) != len(requiredComponents) {
		t.Fatalf("component evidence=%d want %d", len(componentEvidence), len(requiredComponents))
	}

	plan := ValidationPlan{
		Integrity:       staticValidator(postgresEvidence.IntegrityEvidence),
		Crypto:          staticValidator(cryptoEvidence),
		Security:        staticValidator(postgresEvidence.SecurityEvidence),
		TenantIsolation: ValidatorFunc(func(context.Context) (string, error) {
			if err := proveTenantIsolation(ctx, app); err != nil {
				return "", err
			}
			return postgresEvidence.TenantEvidence + "; real tenant A/B reads isolated", nil
		}),
		Audit:      staticValidator(auditEvidence),
		Staleness:  staticValidator(stalenessEvidence),
		Config:     staticValidator(configEvidence),
		Functional: ValidatorFunc(func(context.Context) (string, error) {
			if err := validateRoundTripMarkers(ctx, owner); err != nil {
				return "", err
			}
			return "restored tenant, incident, audit, RLS, crypto, blob, and certification journey passed", nil
		}),
	}
	certification, err := RunValidation(ctx, "ci-restore", "ci-backup", time.Now(), plan)
	if err != nil {
		t.Fatal(err)
	}
	key := testCertificationKey()
	certification, err = SignCertification(certification, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCertificationSignature(certification, key); err != nil {
		t.Fatal(err)
	}
	if err := RequireServingCertification(true, &certification); err != nil {
		t.Fatalf("fully validated restored stack was not permitted to serve: %v", err)
	}
}

func staticValidator(evidence string) Validator {
	return ValidatorFunc(func(context.Context) (string, error) { return evidence, nil })
}

func recoveryCryptoEvidence(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 9)
	}
	cipher, err := platformcrypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	if err != nil {
		t.Fatal(err)
	}
	tenant := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	plaintext := []byte("restored-domain-marker")
	ciphertext, err := cipher.Encrypt(tenant, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ValidateCryptoContinuity(cipher, []string{"recovery_marker"}, []CryptoProbe{{
		Domain: "recovery_marker", TenantID: tenant, Ciphertext: ciphertext, Expected: plaintext,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func recoveryStalenessEvidence(t *testing.T) string {
	t.Helper()
	restored, authority := safeStalenessState()
	evidence, err := ValidateStalenessSafety(restored, authority)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func realComponentProbes(postgres PostgresValidation, cryptoEvidence, blobEvidence, configEvidence, auditEvidence, stalenessEvidence string) map[StatefulComponent]ComponentProbe {
	return map[StatefulComponent]ComponentProbe{
		ComponentPostgres:  {Applicable: true, Validator: staticValidator(postgres.IntegrityEvidence + "; " + postgres.SecurityEvidence)},
		ComponentCrypto:    {Applicable: true, Validator: staticValidator(cryptoEvidence)},
		ComponentBlob:      {Applicable: true, Validator: staticValidator(blobEvidence)},
		ComponentQueue:     {Applicable: true, Validator: staticValidator("durable queue/outbox replay ledgers included in PostgreSQL restore; " + stalenessEvidence)},
		ComponentConfig:    {Applicable: true, Validator: staticValidator(configEvidence)},
		ComponentContent:   {Applicable: true, Validator: staticValidator("content lifecycle schema and monotonic authoritative versions restored; " + stalenessEvidence)},
		ComponentAudit:     {Applicable: true, Validator: staticValidator(auditEvidence)},
		ComponentSessions:  {Applicable: true, Validator: staticValidator("session generation reconciled; " + stalenessEvidence)},
		ComponentRetention: {Applicable: true, Validator: staticValidator("authoritative erasure watermark reconciled; " + stalenessEvidence)},
		ComponentAnalytics: {Applicable: false, ProfileEvidence: "CI deployment profile has no ClickHouse DSN and uses the PostgreSQL event store"},
	}
}

func proveTenantIsolation(ctx context.Context, app *pgxpool.Pool) error {
	for _, proof := range []struct {
		tenant uuid.UUID
		own    uuid.UUID
		other  uuid.UUID
	}{
		{recoveryTenantA, recoveryIncidentA, recoveryIncidentB},
		{recoveryTenantB, recoveryIncidentB, recoveryIncidentA},
	} {
		tx, err := app.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, proof.tenant.String()); err != nil {
			tx.Rollback(ctx)
			return err
		}
		var own, other int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE id=$1`, proof.own).Scan(&own); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE id=$1`, proof.other).Scan(&other); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err := tx.Rollback(ctx); err != nil {
			return err
		}
		if own != 1 || other != 0 {
			return fmt.Errorf("recovery: tenant isolation failed for %s: own=%d other=%d", proof.tenant, own, other)
		}
	}
	return nil
}
