#!/usr/bin/env bash
#
# DR-failover drill — decrypt-at-DR (build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md §2c). RUN, not described.
# Proves the crypto-availability trap: a promoted DR replica can decrypt ONLY if the KEK provider (Vault) is reachable
# from the DR site. With the KEK reachable → the DR instance decrypts (SOC alive). With it unreachable → crypto fails
# closed (dead SOC) — which is exactly why the runbook must provision KEK-at-DR BEFORE failover.
#
# Bonus: this exercises the Vault Transit keyWrapper (built in the KMS gate, previously only httptest-faked) against a
# REAL Vault + real transit key.
#
# Usage (from repo root or backend/):  bash deploy/drills/dr_failover_drill.sh
set -euo pipefail
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

if [ -d backend ] && [ -d deploy/drills ]; then ROOT="$(pwd)"; elif [ -d ../backend ]; then ROOT="$(cd .. && pwd)"; else ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; fi
BACKEND="$ROOT/backend"
EVID_DIR="$ROOT/deploy/drills/evidence"; mkdir -p "$EVID_DIR"
STAMP="$(date +%Y%m%dT%H%M%S)"; EVID="$EVID_DIR/dr_failover_result_$STAMP.txt"

VAULT=nirvet-dr-vault; PRIMARY=nirvet-dr-primary; DR=nirvet-dr-replica
VAULT_ADDR_OK="http://localhost:8200"; VAULT_ADDR_DEAD="http://localhost:1"   # dead = KEK unreachable from DR
PRIMARY_DSN="postgres://postgres:postgres@localhost:55432/nirvet?sslmode=disable"
DR_DSN="postgres://postgres:postgres@localhost:55433/nirvet?sslmode=disable"
DR_MAINT="postgres://postgres:postgres@localhost:55433/postgres?sslmode=disable"
KEY=nirvet-dek

cleanup() { docker rm -f "$VAULT" "$PRIMARY" "$DR" >/dev/null 2>&1 || true; }
trap cleanup EXIT
log() { echo "$@" | tee -a "$EVID"; }

log "=== Nirvet DR-failover drill (decrypt-at-DR) — $STAMP ==="
log "gate: build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md §2c (a promoted DR replica decrypts ONLY if the KEK is reachable)"
cleanup

# ── 1. Vault (the KEK provider) + a transit key ─────────────────────────────────────────────────────────────────
docker run -d --name "$VAULT" --cap-add=IPC_LOCK -p 8200:8200 hashicorp/vault:latest \
  server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200 >/dev/null
for i in $(seq 1 30); do docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root "$VAULT" vault status >/dev/null 2>&1 && break; sleep 1; done
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root "$VAULT" vault secrets enable transit >/dev/null 2>&1 || true
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root "$VAULT" vault write -f "transit/keys/$KEY" >/dev/null
log "[1] Vault up; transit KEK '$KEY' created (real Vault Transit provider)"

# ── 2. primary DB, migrate, seed via the VAULT provider (DEK wrapped by Vault; DB holds only wrapped ciphertext) ──
docker run -d --name "$PRIMARY" -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=nirvet -p 55432:5432 postgres:17 >/dev/null
for i in $(seq 1 30); do docker exec "$PRIMARY" pg_isready -U postgres -d nirvet >/dev/null 2>&1 && break; sleep 1; done
( cd "$BACKEND" && NIRVET_MIGRATE_DATABASE_URL="$PRIMARY_DSN" go run ./cmd/migrate >/dev/null )
( cd "$BACKEND" && NIRVET_DRILL_DSN="$PRIMARY_DSN" NIRVET_CRYPTO_PROVIDER=vault NIRVET_VAULT_ADDR="$VAULT_ADDR_OK" \
    NIRVET_VAULT_TOKEN=root NIRVET_KMS_KEY_NAME="$KEY" go run ./cmd/b8drill seed | tee -a "$EVID" )
log "[2] primary seeded with a Vault-wrapped secret"

# ── 3. 'replicate' primary → DR replica (dump/restore models async replication to the DR site) ──────────────────
docker exec "$PRIMARY" pg_dump -U postgres -Fc nirvet -f /tmp/primary.dump
docker cp "$PRIMARY:/tmp/primary.dump" /tmp/primary.dump >/dev/null
docker run -d --name "$DR" -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=nirvet -p 55433:5432 postgres:17 >/dev/null
for i in $(seq 1 30); do docker exec "$DR" pg_isready -U postgres -d nirvet >/dev/null 2>&1 && break; sleep 1; done
docker cp /tmp/primary.dump "$DR:/tmp/primary.dump" >/dev/null
t0=$SECONDS
docker exec "$DR" pg_restore -U postgres -d nirvet /tmp/primary.dump >/dev/null 2>&1 || true
RTO_S=$((SECONDS - t0))
log "[3] DR replica restored from primary backup (RTO=${RTO_S}s)"

# ── 4. THE TRAP — promote DR with the KEK UNREACHABLE → must fail closed (dead SOC) ──────────────────────────────
if ( cd "$BACKEND" && NIRVET_DRILL_DSN="$DR_DSN" NIRVET_CRYPTO_PROVIDER=vault NIRVET_VAULT_ADDR="$VAULT_ADDR_DEAD" \
     NIRVET_VAULT_TOKEN=root NIRVET_KMS_KEY_NAME="$KEY" go run ./cmd/b8drill verify >/dev/null 2>&1 ); then
  log "[4] FAIL: DR decrypted with the KEK UNREACHABLE — the decrypt-at-DR dependency is not real"; exit 1
else
  log "[4] TRAP PASS: with the KEK provider unreachable, the DR replica CANNOT decrypt (fails closed = dead SOC)."
  log "    → the runbook MUST provision KEK-reachability at DR before failover is possible."
fi

# ── 5. THE FIX — KEK reachable from DR → the promoted replica decrypts (SOC alive) ───────────────────────────────
if ( cd "$BACKEND" && NIRVET_DRILL_DSN="$DR_DSN" NIRVET_CRYPTO_PROVIDER=vault NIRVET_VAULT_ADDR="$VAULT_ADDR_OK" \
     NIRVET_VAULT_TOKEN=root NIRVET_KMS_KEY_NAME="$KEY" go run ./cmd/b8drill verify 2>&1 | tee -a "$EVID" ); then
  log "[5] DECRYPT-AT-DR PASS: with the KEK reachable, the promoted DR replica decrypted the secret (SOC alive)."
else
  log "[5] FAIL: DR could not decrypt even with the KEK reachable — DR is not usable"; exit 1
fi

log ""
log "=== DR-FAILOVER DRILL RESULT: PASS ==="
log "Invariant proven (decrypt-at-DR): KEK unreachable → DR fails closed (dead SOC); KEK reachable → DR decrypts."
log "This also validated the Vault Transit keyWrapper end-to-end against a REAL Vault (not the httptest fake)."
log "Split-brain: out of scope for this drill — the runbook fences the old primary on promotion (single-writer)."
log "DR restore RTO (this hardware): ${RTO_S}s.   Evidence: $EVID"
rm -f /tmp/primary.dump
