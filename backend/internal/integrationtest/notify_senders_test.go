package integrationtest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/ArowuTest/nirvet/internal/notify"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestIntegration_NotificationSenders exercises §6.16 slice B: per-tenant email/SMS sender config with a
// vault-encrypted secret (COMM-001) — the secret round-trips through the cipher, is never returned, and
// is isolated per tenant.
func TestIntegration_NotificationSenders(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run integration tests")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cipher, _ := crypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)

	tenSvc := tenant.NewService(tenant.NewRepository(db))
	tnA, _ := tenSvc.Create(ctx, tenant.CreateInput{Name: "notify-A-" + uuid.NewString()})
	tnB, _ := tenSvc.Create(ctx, tenant.CreateInput{Name: "notify-B-" + uuid.NewString()})

	repo := notify.NewSenderRepo(db)
	svc := notify.NewService(discardLogger()).WithSenders(repo, cipher, notify.DefaultSMSClient())

	// Configure an email sender for tenant A with a secret.
	if err := svc.ConfigureSender(ctx, tnA.ID, notify.SenderInput{
		Channel: "email", FromAddress: "soc@acme.example", SMTPHost: "smtp.acme.example",
		SMTPPort: 587, SMTPUsername: "soc", Secret: "smtp-password-123",
	}); err != nil {
		t.Fatalf("configure email sender: %v", err)
	}
	// Invalid: email requires smtp_host + from_address.
	if err := svc.ConfigureSender(ctx, tnA.ID, notify.SenderInput{Channel: "email"}); err == nil {
		t.Fatal("email sender without smtp_host must be rejected")
	}
	// Invalid channel.
	if err := svc.ConfigureSender(ctx, tnA.ID, notify.SenderInput{Channel: "carrier-pigeon"}); err == nil {
		t.Fatal("unknown channel must be rejected")
	}

	// List returns the sender with HasSecret=true but never the secret itself.
	senders, err := svc.ListSenders(ctx, tnA.ID)
	if err != nil || len(senders) != 1 {
		t.Fatalf("expected 1 sender, got %d (%v)", len(senders), err)
	}
	if senders[0].Channel != "email" || !senders[0].HasSecret || senders[0].SMTPHost != "smtp.acme.example" {
		t.Fatalf("sender config wrong: %+v", senders[0])
	}

	// Tenant isolation: tenant B sees no senders.
	bSenders, _ := svc.ListSenders(ctx, tnB.ID)
	if len(bSenders) != 0 {
		t.Fatalf("tenant B must not see tenant A senders, got %d", len(bSenders))
	}

	// Update without a secret keeps the existing one (COALESCE); disabling works.
	off := false
	if err := svc.ConfigureSender(ctx, tnA.ID, notify.SenderInput{
		Channel: "email", FromAddress: "soc2@acme.example", SMTPHost: "smtp.acme.example", SMTPPort: 587, Enabled: &off,
	}); err != nil {
		t.Fatalf("update sender: %v", err)
	}
	senders, _ = svc.ListSenders(ctx, tnA.ID)
	if !senders[0].HasSecret || senders[0].Enabled {
		t.Fatalf("secret should persist and sender be disabled: %+v", senders[0])
	}

	// SMS sender requires a provider_url.
	if err := svc.ConfigureSender(ctx, tnA.ID, notify.SenderInput{Channel: "sms", FromAddress: "NIRVET"}); err == nil {
		t.Fatal("sms sender without provider_url must be rejected")
	}
	if err := svc.ConfigureSender(ctx, tnA.ID, notify.SenderInput{
		Channel: "sms", FromAddress: "NIRVET", ProviderURL: "https://sms.example/send", Secret: "api-key",
	}); err != nil {
		t.Fatalf("configure sms sender: %v", err)
	}
	senders, _ = svc.ListSenders(ctx, tnA.ID)
	if len(senders) != 2 {
		t.Fatalf("expected email + sms senders, got %d", len(senders))
	}
}
