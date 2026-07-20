#!/usr/bin/env bash
#
# B8 backup/restore drill (build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md §2a) — RUN, not described.
# Proves, end-to-end against a real Postgres, the two traps a wrong runbook hits:
#   (a) the DB backup holds ONLY KMS-wrapped ciphertext — the KEK is backed up SEPARATELY and never appears in the dump;
#   (b) a restored instance can DECRYPT with the separately-held KEK (and CANNOT without it — DB-alone is unreadable).
# Captures RPO/RTO and writes a signed-off-able evidence file. Fails hard if any invariant is violated.
#
# Usage (from repo root or backend/):  bash deploy/drills/b8_backup_restore.sh
set -euo pipefail

# Windows git-bash rewrites unix-absolute paths (e.g. the container-side /tmp/data.dump) before passing them to
# `docker exec`. Disable that so container paths reach the container verbatim. (No-op on Linux CI.)
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

# ── locate dirs ────────────────────────────────────────────────────────────────────────────────────────────────
if [ -d backend ] && [ -d deploy/drills ]; then ROOT="$(pwd)"; elif [ -d ../backend ]; then ROOT="$(cd .. && pwd)"; else ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; fi
BACKEND="$ROOT/backend"
EVID_DIR="$ROOT/deploy/drills/evidence"
mkdir -p "$EVID_DIR"
STAMP="$(date +%Y%m%dT%H%M%S)"
EVID="$EVID_DIR/b8_result_$STAMP.txt"

CONTAINER="nirvet-b8-drill"
PORT=55432
DSN="postgres://postgres:postgres@localhost:$PORT/nirvet?sslmode=disable"
DSN_MAINT="postgres://postgres:postgres@localhost:$PORT/postgres?sslmode=disable"
MARKER="B8-DRILL-PLAINTEXT-SECRET-do-not-appear-in-backup"

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

log() { echo "$@" | tee -a "$EVID"; }

log "=== Nirvet B8 backup/restore drill — $STAMP ==="
log "gate: build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md §2a (backup covers wrapped data; KEK separate; restore decrypts)"

# ── 1. stand up a real Postgres 17 (the 'primary') ──────────────────────────────────────────────────────────────
cleanup
docker run -d --name "$CONTAINER" -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=nirvet -p "$PORT:5432" postgres:17 >/dev/null
log "[1] started postgres:17 container (primary) on :$PORT"
for i in $(seq 1 30); do docker exec "$CONTAINER" pg_isready -U postgres -d nirvet >/dev/null 2>&1 && break; sleep 1; done
docker exec "$CONTAINER" pg_isready -U postgres -d nirvet >/dev/null

# ── 2. real schema + the KEK held SEPARATELY from the DB ─────────────────────────────────────────────────────────
( cd "$BACKEND" && NIRVET_MIGRATE_DATABASE_URL="$DSN" go run ./cmd/migrate >/dev/null )
log "[2] migrations applied (full production schema)"
KEK="$(openssl rand -base64 32 2>/dev/null || head -c32 /dev/urandom | base64)"   # the KEK — lives in env/a file, NEVER the DB
WRONG_KEK="$(openssl rand -base64 32 2>/dev/null || head -c32 /dev/urandom | base64)"

# ── 3. seed: encrypt a known secret under the KEK; store ONLY the wrapped ciphertext ─────────────────────────────
( cd "$BACKEND" && NIRVET_DRILL_DSN="$DSN" NIRVET_SECRET_MASTER_KEY="$KEK" go run ./cmd/b8drill seed | tee -a "$EVID" )

# ── 4. BACKUP (measure duration) — the data backup ──────────────────────────────────────────────────────────────
t0=$SECONDS
docker exec "$CONTAINER" pg_dump -U postgres -Fc nirvet -f /tmp/data.dump
BACKUP_S=$((SECONDS - t0))
DUMP_BYTES="$(docker exec "$CONTAINER" sh -c 'stat -c %s /tmp/data.dump')"
log "[4] backup taken: pg_dump custom-format, ${DUMP_BYTES} bytes, ${BACKUP_S}s"

# ── 5. TRAP (a): the plaintext secret and the KEK are ABSENT from the backup (only wrapped ciphertext is in it) ───
docker exec "$CONTAINER" pg_restore -f /tmp/plain.sql /tmp/data.dump
if docker exec "$CONTAINER" grep -qF "$MARKER" /tmp/plain.sql; then
  log "[5] FAIL: plaintext secret found in the backup — data is NOT wrapped"; exit 1
fi
if docker exec "$CONTAINER" grep -qF "$KEK" /tmp/plain.sql; then
  log "[5] FAIL: the KEK leaked into the backup — catastrophic"; exit 1
fi
log "[5] TRAP (a) PASS: neither the plaintext nor the KEK appears in the backup — DB holds only wrapped ciphertext"

# ── 6. WIPE + RESTORE into a fresh database (measure RTO) ────────────────────────────────────────────────────────
psql "$DSN_MAINT" -v ON_ERROR_STOP=1 -c "DROP DATABASE nirvet WITH (FORCE);" -c "CREATE DATABASE nirvet;" >/dev/null 2>&1 \
  || docker exec "$CONTAINER" psql -U postgres -d postgres -c "DROP DATABASE nirvet WITH (FORCE);" -c "CREATE DATABASE nirvet;" >/dev/null
log "[6] primary DB wiped (simulated loss)"
t0=$SECONDS
docker exec "$CONTAINER" pg_restore -U postgres -d nirvet /tmp/data.dump >/dev/null 2>&1 || true
RTO_S=$((SECONDS - t0))
log "[6] restore completed into a fresh DB: RTO=${RTO_S}s"

# ── 7. TRAP (b): restored instance DECRYPTS with the separately-held KEK; and FAILS without it ───────────────────
if ( cd "$BACKEND" && NIRVET_DRILL_DSN="$DSN" NIRVET_SECRET_MASTER_KEY="$KEK" go run ./cmd/b8drill verify 2>&1 | tee -a "$EVID" ); then
  log "[7] TRAP (b) PASS: restored instance decrypted the secret with the separately-backed-up KEK (smoke pass)"
else
  log "[7] FAIL: restored instance could NOT decrypt with the correct KEK — restore is not usable"; exit 1
fi
if ( cd "$BACKEND" && NIRVET_DRILL_DSN="$DSN" NIRVET_SECRET_MASTER_KEY="$WRONG_KEK" go run ./cmd/b8drill verify >/dev/null 2>&1 ); then
  log "[7] FAIL: a WRONG key decrypted the data — the KEK is not actually protecting it"; exit 1
else
  log "[7] NEGATIVE-CONTROL PASS: with a wrong/absent KEK the restored DB is UNREADABLE (as required)"
fi

# ── 8. evidence summary (RPO/RTO) ───────────────────────────────────────────────────────────────────────────────
log ""
log "=== B8 DRILL RESULT: PASS ==="
log "RTO (measured restore time on this hardware): ${RTO_S}s   [backup: ${BACKUP_S}s, ${DUMP_BYTES} bytes]"
log "RPO: 0 for this drill (backup taken immediately after the last write; no committed data lost)."
log "     Production RPO = the scheduled backup interval (the runbook sets it; e.g. WAL-archiving → seconds)."
log "Invariants proven: (a) backup = wrapped ciphertext only, KEK separate & absent from dump;"
log "                   (b) restore + separately-held KEK decrypts (smoke pass); wrong/absent key = unreadable."
log "Evidence file: $EVID"
