// Command b8drill is the crypto half of the B8 backup/restore drill (build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md §2a).
// It exercises the REAL crypto package so the drill proves the KEK-separation invariant, not a doc claim:
//
//	seed   — encrypt a known secret under the master key (the KEK, from NIRVET_SECRET_MASTER_KEY) and store ONLY the
//	         AES-256-GCM ciphertext in the database. The KEK never enters the DB — it lives separately in env/a file,
//	         which is exactly what a real deployment backs up on its own procedure (Vault/HSM key, or the master key).
//	verify — read the ciphertext back from the (restored) database and decrypt it with the master key, asserting the
//	         plaintext round-trips. This is the "restored instance boots + decrypts (KEK available) + smoke passes"
//	         check: exit 0 iff decrypt succeeds AND matches. With a wrong/absent key, AES-GCM auth fails → exit 1,
//	         proving the DB backup alone (no key) restores UNREADABLE data.
//
// DSN in NIRVET_DRILL_DSN. The drill secret is a fixed marker so the orchestration can grep the dump for it.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// drillPlaintext is the known secret. The orchestration asserts this literal is NOT present in the DB dump (the
// backup holds only wrapped ciphertext) — so keep it a distinctive, greppable marker.
const drillPlaintext = "B8-DRILL-PLAINTEXT-SECRET-do-not-appear-in-backup"

// drillTenant is a fixed tenant id so seed and verify bind the same GCM AAD.
var drillTenant = uuid.MustParse("b8d00000-0000-0000-0000-00000000b8d1")

func main() {
	if len(os.Args) < 2 {
		die("usage: b8drill seed|verify")
	}
	dsn := os.Getenv("NIRVET_DRILL_DSN")
	if dsn == "" {
		die("NIRVET_DRILL_DSN is required")
	}
	// Build the cipher from env so ONE helper serves both drills: the B8 backup/restore drill uses the master key
	// (localCipher, the KEK held separately in env/a file); the DR-failover drill sets NIRVET_CRYPTO_PROVIDER=vault so
	// the KEK is a NETWORK-reachable Vault Transit provider — and "reachable from DR" becomes a real, testable
	// condition (unreachable Vault → crypto init/decrypt fails → the DR replica is a dead SOC, which is the point).
	mount := os.Getenv("NIRVET_VAULT_MOUNT")
	if mount == "" {
		mount = "transit"
	}
	cipher, err := crypto.NewFromConfig(crypto.Config{
		Provider:     os.Getenv("NIRVET_CRYPTO_PROVIDER"),
		KeyName:      os.Getenv("NIRVET_KMS_KEY_NAME"),
		MasterKeyB64: os.Getenv("NIRVET_SECRET_MASTER_KEY"),
		VaultAddr:    os.Getenv("NIRVET_VAULT_ADDR"),
		VaultMount:   mount,
	})
	if err != nil {
		die("crypto init (KEK provider unreachable/misconfigured — a DR replica cannot serve without its KEK): %v", err)
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		die("connect: %v", err)
	}
	defer conn.Close(ctx)

	switch os.Args[1] {
	case "seed":
		if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS b8_drill (id int PRIMARY KEY, tenant uuid NOT NULL, ciphertext bytea NOT NULL)`); err != nil {
			die("create table: %v", err)
		}
		ct, err := cipher.Encrypt(drillTenant, []byte(drillPlaintext))
		if err != nil {
			die("encrypt: %v", err)
		}
		if _, err := conn.Exec(ctx,
			`INSERT INTO b8_drill (id, tenant, ciphertext) VALUES (1,$1,$2)
			 ON CONFLICT (id) DO UPDATE SET tenant=EXCLUDED.tenant, ciphertext=EXCLUDED.ciphertext`,
			drillTenant, ct); err != nil {
			die("insert: %v", err)
		}
		fmt.Printf("seeded: %d bytes of wrapped ciphertext stored; plaintext + KEK held OUTSIDE the DB\n", len(ct))

	case "verify":
		var tenant uuid.UUID
		var ct []byte
		if err := conn.QueryRow(ctx, `SELECT tenant, ciphertext FROM b8_drill WHERE id=1`).Scan(&tenant, &ct); err != nil {
			die("read restored ciphertext: %v", err)
		}
		pt, err := cipher.Decrypt(tenant, ct)
		if err != nil {
			// Wrong/absent KEK → AES-GCM auth fails. This is the point: the DB backup alone is unreadable.
			die("DECRYPT FAILED (KEK unavailable/incorrect — DB backup alone is unreadable): %v", err)
		}
		if string(pt) != drillPlaintext {
			die("DECRYPT MISMATCH: restored plaintext does not match the seeded secret")
		}
		fmt.Println("DECRYPT OK: restored instance decrypted the secret with the separately-held KEK — smoke pass")

	default:
		die("unknown mode %q (want seed|verify)", os.Args[1])
	}
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "b8drill: "+format+"\n", a...)
	os.Exit(1)
}
