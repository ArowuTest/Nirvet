#!/usr/bin/env bash
set -euo pipefail

root="internal/platform/contentlifecycle"
if [[ ! -d "$root" ]]; then
  echo "content import boundary missing: $root" >&2
  exit 1
fi

# Imported content is data only. Standard-library crypto primitives are required
# to verify signatures and hashes, but the content path must not import Nirvet's
# authority, KMS/crypto, SOAR, connector, or other mutation-capable packages.
# Scan production Go only: falsification tests intentionally contain forbidden
# strings such as raw_sql/soar_action and must not trip the structural fence.
grep_prod() {
  grep -RInE --include='*.go' --exclude='*_test.go' "$1" "$root"
}

forbidden_import='"[^"\n]*/(soar|actioner|connector|authority|crypto|config)(/[^"\n]*)?"'
forbidden_symbol='(^|[^[:alnum:]_])(os/exec|syscall|plugin|reflect|unsafe|eval|exec\.Command|soar|actioner|authority|grant|configwrite|config_write)([^[:alnum:]_]|$)'

if grep_prod "$forbidden_import"; then
  echo "content import boundary violation: forbidden platform dependency" >&2
  exit 1
fi

if grep_prod "$forbidden_symbol"; then
  echo "content import boundary violation: forbidden execution or mutation symbol" >&2
  exit 1
fi

# Raw SQL is never a content interpretation mechanism. Persistence adapters may
# live outside this package behind narrow interfaces.
if grep_prod '(database/sql|sqlx|gorm|pgx|raw[_ -]?sql)'; then
  echo "content import boundary violation: persistence or raw SQL in interpretation core" >&2
  exit 1
fi

echo "content import boundary: data-only interpretation core confirmed"
