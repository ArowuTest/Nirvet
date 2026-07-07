package connector

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/queue"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// mockGraph serves the OAuth token and a single Defender-style alert.
func mockGraph(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"test-token","expires_in":3600}`)
	})
	mux.HandleFunc("/security/alerts_v2", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"value":[{
			"id":"defender-alert-001","title":"Ransomware activity","severity":"high",
			"category":"Ransomware","createdDateTime":"2026-07-07T10:00:00Z",
			"deviceName":"WIN-EDR-3","accountName":"victim","mitreTechniques":["T1486"]}]}`)
	})
	return httptest.NewServer(mux)
}

func TestPollerIngestsFromGraph(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run the poller integration test")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	srv := mockGraph(t)
	t.Cleanup(srv.Close)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cipher, _ := crypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	vault := NewVault(cipher)
	blobs, _ := blobstore.NewLocal(t.TempDir())
	ingestSvc := ingestion.NewService(ingestion.NewRepository(db), queue.NewPostgres(db.Pool), nil, blobs)
	repo := NewRepository(db)
	connSvc := NewService(repo, vault, ingestSvc)

	tenantID := uuid.New()
	res, err := connSvc.Create(ctx, tenantID, CreateInput{
		Kind: KindDefender, Name: "defender-pull", Secret: "the-client-secret",
		Config: map[string]any{"client_id": "cid", "azure_tenant": "az"},
	})
	if err != nil {
		t.Fatalf("create connector: %v", err)
	}
	connID := res.Connector.ID
	t.Cleanup(func() { _ = connSvc.Delete(ctx, tenantID, connID) })

	poller := NewPoller(repo, vault, ingestSvc, log).WithEndpoints(srv.URL+"/token", srv.URL)
	if _, err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}

	// The pulled alert must have been ingested into THIS tenant (evidence stored).
	var n int
	if err := db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM raw_events WHERE source='microsoft-defender' AND dedupe_key=$1`,
			"microsoft-defender:defender-alert-001").Scan(&n)
	}); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected the pulled Defender alert ingested once, got %d", n)
	}

	// The connector checkpoint must advance to the alert's timestamp.
	var checkpoint string
	_ = db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(config->>'checkpoint','') FROM connector_configs WHERE id=$1`, connID).Scan(&checkpoint)
	})
	if checkpoint != "2026-07-07T10:00:00Z" {
		t.Fatalf("checkpoint not advanced: %q", checkpoint)
	}
}
