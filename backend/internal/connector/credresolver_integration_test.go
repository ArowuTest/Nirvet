package connector

// §6.11 slice C C-1 — the real CredDecryptor round-trips a tenant's vault-sealed connector secret +
// config into the opaque bundle a vendor Actioner consumes, and fails closed when the tenant has no
// such connector. Gated on NIRVET_TEST_DATABASE_URL (fails under CI when unset).

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/google/uuid"
)

func TestCredentialResolver_ConnectorCreds(t *testing.T) {
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cipher, _ := crypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	vault := NewVault(cipher)
	repo := NewRepository(db)
	svc := NewService(repo, vault, nil)

	tenantID := uuid.New()
	if _, err := svc.Create(ctx, tenantID, CreateInput{
		Kind: KindDefender, Name: "defender-action", Secret: "the-client-secret",
		Config: map[string]any{"client_id": "cid-123", "azure_tenant": "az-tid"},
	}); err != nil {
		t.Fatalf("create connector: %v", err)
	}

	resolver := NewCredentialResolver(repo, vault)

	// Happy path: the resolved bundle carries the decrypted secret + config verbatim.
	raw, err := resolver.ConnectorCreds(ctx, tenantID, string(KindDefender))
	if err != nil {
		t.Fatalf("ConnectorCreds: %v", err)
	}
	var got Credentials
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	if got.ClientID != "cid-123" || got.ClientSecret != "the-client-secret" || got.AzureTenant != "az-tid" {
		t.Fatalf("bundle mismatch: %+v", got)
	}

	// Fail closed: a kind the tenant never configured returns an error (no credentials to act with).
	if _, err := resolver.ConnectorCreds(ctx, tenantID, string(KindEntraID)); err == nil {
		t.Fatal("expected error for a kind the tenant has no connector for")
	}
	// Fail closed: another tenant cannot resolve this tenant's connector (RLS isolation).
	if _, err := resolver.ConnectorCreds(ctx, uuid.New(), string(KindDefender)); err == nil {
		t.Fatal("expected error resolving a different tenant's connector (RLS)")
	}
}
