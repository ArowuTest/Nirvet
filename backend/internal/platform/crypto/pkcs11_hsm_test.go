//go:build hsm

package crypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
)

// These tests are intentionally fatal when the SoftHSM contract is absent. A skipped HSM
// suite is not evidence that the hardware-provider path works (GATE_KMS_INCREMENT2_HSM §3).
func requireHSM(t *testing.T) Config {
	t.Helper()
	module := strings.TrimSpace(os.Getenv(defaultPKCS11ModuleEnv))
	pin := strings.TrimSpace(os.Getenv(defaultPKCS11PINEnv))
	label := strings.TrimSpace(os.Getenv(defaultPKCS11TokenLabelEnv))
	probe := strings.TrimSpace(os.Getenv(defaultPKCS11ProbeKeyEnv))
	if module == "" || pin == "" || label == "" || probe == "" {
		t.Fatalf("HSM test contract missing: require %s, %s, %s and %s; tests must not skip",
			defaultPKCS11ModuleEnv, defaultPKCS11PINEnv, defaultPKCS11TokenLabelEnv, defaultPKCS11ProbeKeyEnv)
	}
	return Config{
		Provider:        "pkcs11",
		KeyName:         "nirvet-tenant-{tenant}",
		RequireKMS:      true,
		HSMModulePath:   module,
		HSMTokenLabel:   label,
		HSMProbeKeyName: probe,
		HSMPIN:          pin,
	}
}

func provisionTestKEK(t *testing.T, cfg Config, keyName string) {
	t.Helper()
	p := pkcs11.New(cfg.HSMModulePath)
	if p == nil {
		t.Fatalf("load PKCS#11 module %q", cfg.HSMModulePath)
	}
	defer p.Destroy()
	if err := p.Initialize(); err != nil && err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		t.Fatalf("initialize PKCS#11 module: %v", err)
	}
	defer func() { _ = p.Finalize() }()

	slot, err := resolvePKCS11Slot(p, cfg.HSMSlotID, cfg.HSMTokenLabel)
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	defer func() { _ = p.CloseSession(session) }()
	if err := p.Login(session, pkcs11.CKU_USER, cfg.HSMPIN); err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = p.Logout(session) }()

	id := sha256.Sum256([]byte(keyName))
	search := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyName),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id[:16]),
	}
	if err := p.FindObjectsInit(session, search); err != nil {
		t.Fatalf("find init: %v", err)
	}
	objects, _, findErr := p.FindObjects(session, 1)
	finalErr := p.FindObjectsFinal(session)
	if findErr != nil || finalErr != nil {
		t.Fatalf("find existing key: find=%v final=%v", findErr, finalErr)
	}
	if len(objects) == 1 {
		return
	}

	_, err = p.GenerateKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyName),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id[:16]),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	})
	if err != nil {
		t.Fatalf("generate non-extractable test KEK %q: %v", keyName, err)
	}
}

func preparedHSM(t *testing.T) (Config, *pkcs11Wrapper, uuid.UUID, uuid.UUID) {
	t.Helper()
	cfg := requireHSM(t)
	tenantA := uuid.New()
	tenantB := uuid.New()
	keyA := strings.ReplaceAll(cfg.KeyName, tenantPlaceholder, tenantA.String())
	keyB := strings.ReplaceAll(cfg.KeyName, tenantPlaceholder, tenantB.String())
	provisionTestKEK(t, cfg, cfg.HSMProbeKeyName)
	provisionTestKEK(t, cfg, keyA)
	provisionTestKEK(t, cfg, keyB)
	wrapper, tag, err := buildPKCS11Wrapper(cfg)
	if err != nil {
		t.Fatalf("build PKCS#11 wrapper: %v", err)
	}
	if tag != tagPKCS11 {
		t.Fatalf("provider tag = %v, want pkcs11", tag)
	}
	return cfg, wrapper.(*pkcs11Wrapper), tenantA, tenantB
}

// #1 + #5: real-token round trip and per-tenant key-object isolation. PKCS#11 AES key wrap
// has no AAD input; isolation is the distinct keyNameFor({tenant}) object, while the envelope
// payload remains independently tenant-bound by AES-GCM AAD.
func TestPKCS11_RoundTripAndPerTenantIsolation(t *testing.T) {
	cfg, wrapper, tenantA, tenantB := preparedHSM(t)
	dek := bytes.Repeat([]byte{0x42}, 32)
	keyA := strings.ReplaceAll(cfg.KeyName, tenantPlaceholder, tenantA.String())
	keyB := strings.ReplaceAll(cfg.KeyName, tenantPlaceholder, tenantB.String())
	wrapped, err := wrapper.Wrap(context.Background(), keyA, dek, tenantA[:])
	if err != nil {
		t.Fatalf("wrap tenant A: %v", err)
	}
	got, err := wrapper.Unwrap(context.Background(), keyA, wrapped, tenantA[:])
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("tenant A round-trip: got=%x err=%v", got, err)
	}
	if _, err := wrapper.Unwrap(context.Background(), keyB, wrapped, tenantB[:]); err == nil {
		t.Fatal("tenant B KEK must not unwrap tenant A's wrapped DEK")
	}
}

// #2: the provisioned KEK is sensitive/non-extractable and CKA_VALUE cannot be read.
func TestPKCS11_KEKCannotBeExported(t *testing.T) {
	cfg, wrapper, tenantA, _ := preparedHSM(t)
	keyName := strings.ReplaceAll(cfg.KeyName, tenantPlaceholder, tenantA.String())
	err := wrapper.withSession(func(session pkcs11.SessionHandle) error {
		key, err := wrapper.findKEK(session, keyName)
		if err != nil {
			return err
		}
		_, err = wrapper.ctx.GetAttributeValue(session, key, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
		return err
	})
	if err == nil {
		t.Fatal("reading CKA_VALUE for a sensitive, non-extractable KEK must be refused")
	}
}

// #3: wrong PIN fails during the mandatory real-token boot probe; there is no local fallback.
func TestPKCS11_WrongPINFailsClosedAtBoot(t *testing.T) {
	cfg := requireHSM(t)
	provisionTestKEK(t, cfg, cfg.HSMProbeKeyName)
	cfg.HSMPIN = "definitely-wrong"
	if _, _, err := buildPKCS11Wrapper(cfg); err == nil {
		t.Fatal("wrong HSM PIN must fail closed at boot")
	}
}

// #4: provider tag confusion is rejected before any HSM unwrap attempt.
func TestPKCS11_ProviderConfusionRefused(t *testing.T) {
	cfg, wrapper, tenantA, _ := preparedHSM(t)
	hsmEnv := newEnvelopeCipher(wrapper, cfg.KeyName, tagPKCS11, 1)
	vaultEnv := newEnvelopeCipher(&fakeWrapper{}, cfg.KeyName, tagVault, 1)
	blob, err := hsmEnv.Encrypt(tenantA, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt HSM blob: %v", err)
	}
	if _, err := vaultEnv.Decrypt(tenantA, blob); err == nil || !strings.Contains(err.Error(), "provider mismatch") {
		t.Fatalf("cross-provider decrypt must refuse loudly, got %v", err)
	}
}

// #6: old-provider ciphertext remains readable while all new writes use HSM.
func TestPKCS11_DualReadMigrationDoesNotOrphanVault(t *testing.T) {
	cfg, wrapper, tenantA, _ := preparedHSM(t)
	legacy := newEnvelopeCipher(&fakeWrapper{}, cfg.KeyName, tagVault, 1)
	current := newEnvelopeCipher(wrapper, cfg.KeyName, tagPKCS11, 1)
	oldBlob, err := legacy.Encrypt(tenantA, []byte("old"))
	if err != nil {
		t.Fatalf("legacy encrypt: %v", err)
	}
	transition := &transitionCipher{writer: current, readers: []*envelopeCipher{legacy}}
	got, err := transition.Decrypt(tenantA, oldBlob)
	if err != nil || !bytes.Equal(got, []byte("old")) {
		t.Fatalf("legacy decrypt during migration: got=%q err=%v", got, err)
	}
	newBlob, err := transition.Encrypt(tenantA, []byte("new"))
	if err != nil {
		t.Fatalf("HSM write during migration: %v", err)
	}
	if providerTag(newBlob[1]) != tagPKCS11 {
		t.Fatalf("new write tag=%v, want pkcs11", providerTag(newBlob[1]))
	}
}

// #7: require-KMS accepts the real HSM provider but never uses localCipher.
func TestPKCS11_RequireKMSSelectsHSM(t *testing.T) {
	cfg, _, tenantA, _ := preparedHSM(t)
	cipher, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig HSM: %v", err)
	}
	blob, err := cipher.Encrypt(tenantA, []byte("hsm-only"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(blob) < 2 || providerTag(blob[1]) != tagPKCS11 {
		t.Fatalf("cipher did not select PKCS#11 provider: %x", blob)
	}
}

// #8 is shared machinery: envelopeCipher still owns and zeroizes the DEK. The
// mutation-sensitive TestEnvelope_DEKZeroized runs in this same tagged CI job.
func TestPKCS11_ProviderImplementsKeyWrapperOnly(t *testing.T) {
	_, wrapper, _, _ := preparedHSM(t)
	var _ keyWrapper = wrapper
}
