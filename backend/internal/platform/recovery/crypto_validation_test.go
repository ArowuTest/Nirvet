package recovery

import (
	"encoding/base64"
	"errors"
	"testing"

	platformcrypto "github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/google/uuid"
)

func testRecoveryCipher(t *testing.T) platformcrypto.SecretCipher {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := platformcrypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func TestValidateCryptoContinuity_AllDomainsDecrypt(t *testing.T) {
	cipher := testRecoveryCipher(t)
	tenantA := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	tenantB := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	connectorPlain := []byte("connector-secret-marker")
	aiPlain := []byte("ai-provider-key-marker")
	connectorCT, err := cipher.Encrypt(tenantA, connectorPlain)
	if err != nil {
		t.Fatal(err)
	}
	aiCT, err := cipher.Encrypt(tenantB, aiPlain)
	if err != nil {
		t.Fatal(err)
	}

	evidence, err := ValidateCryptoContinuity(cipher,
		[]string{"connector_credentials", "ai_provider_keys"},
		[]CryptoProbe{
			{Domain: "connector_credentials", TenantID: tenantA, Ciphertext: connectorCT, Expected: connectorPlain},
			{Domain: "ai_provider_keys", TenantID: tenantB, Ciphertext: aiCT, Expected: aiPlain},
		})
	if err != nil {
		t.Fatal(err)
	}
	if evidence == "" {
		t.Fatal("successful crypto validation returned no evidence")
	}
}

func TestValidateCryptoContinuity_WrongTenantFailsClosed(t *testing.T) {
	cipher := testRecoveryCipher(t)
	tenantA := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	tenantB := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	plain := []byte("tenant-bound-secret")
	ciphertext, err := cipher.Encrypt(tenantA, plain)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ValidateCryptoContinuity(cipher, []string{"connector_credentials"}, []CryptoProbe{{
		Domain: "connector_credentials", TenantID: tenantB, Ciphertext: ciphertext, Expected: plain,
	}})
	if err == nil {
		t.Fatal("wrong tenant unexpectedly decrypted restored ciphertext")
	}
}

func TestValidateCryptoContinuity_MissingDomainFailsClosed(t *testing.T) {
	cipher := testRecoveryCipher(t)
	_, err := ValidateCryptoContinuity(cipher, []string{"connector_credentials", "ai_provider_keys"}, nil)
	if err == nil {
		t.Fatal("missing encrypted-domain probes were certified")
	}
}

func TestValidateCryptoContinuity_WrongKeyFailsClosed(t *testing.T) {
	correct := testRecoveryCipher(t)
	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = byte(255 - i)
	}
	wrong, err := platformcrypto.NewLocal(base64.StdEncoding.EncodeToString(wrongKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	tenant := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	plain := []byte("restored-secret")
	ciphertext, err := correct.Encrypt(tenant, plain)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ValidateCryptoContinuity(wrong, []string{"connector_credentials"}, []CryptoProbe{{
		Domain: "connector_credentials", TenantID: tenant, Ciphertext: ciphertext, Expected: plain,
	}})
	if err == nil || errors.Is(err, nil) {
		t.Fatal("wrong KEK unexpectedly passed crypto recovery validation")
	}
}
