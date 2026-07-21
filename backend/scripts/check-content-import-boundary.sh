#!/usr/bin/env bash
set -euo pipefail

root="internal/platform/contentlifecycle"
if [[ ! -d "$root" ]]; then
  echo "content import boundary missing: $root" >&2
  exit 1
fi

# Imported content is data only. This package must not gain execution, response,
# authority, crypto, connector, or configuration-mutation capabilities.
forbidden='(^|[^[:alnum:]_])(os/exec|syscall|plugin|reflect|unsafe|eval|soar|actioner|connector|authority|crypto|grant|role|configwrite|config_write)([^[:alnum:]_]|$)'

if grep -RInE --include='*.go' "$forbidden" "$root"; then
  echo "content import boundary violation: forbidden execution or mutation dependency" >&2
  exit 1
fi

# Raw SQL is never a content interpretation mechanism. Persistence adapters may
# live outside this package behind narrow interfaces.
if grep -RInE --include='*.go' '(database/sql|sqlx|gorm|pgx|raw[_ -]?sql)' "$root"; then
  echo "content import boundary violation: persistence or raw SQL in interpretation core" >&2
  exit 1
fi

echo "content import boundary: data-only interpretation core confirmed"
