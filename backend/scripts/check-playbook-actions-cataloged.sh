#!/usr/bin/env bash
#
# check-playbook-actions-cataloged.sh — CI teeth behind #186's "no silently-broken playbook content" invariant.
#
# A seeded SOAR playbook step names an `action`. At runtime that action_key is resolved against
# soar_action_catalog to get its §9.5 risk class + executor. An action_key ABSENT from the catalog FAILS CLOSED
# to 'business_critical' (max approval) — the step can never run. That is a safe failure (a broken template can't
# fire a destructive action), but it is a SILENTLY-broken template: the content ships looking complete and is
# inert. This fence makes that structural: every `action` in any seeded playbook step MUST be a seeded catalog
# action_key. Applies to current AND future content packs, so new seeds can't reintroduce the trap.
#
# Run from backend/. Exits non-zero listing any playbook action not present in the catalog seed.
set -euo pipefail

cd "$(dirname "$0")/.."
MIG=migrations

# Catalog action_keys: the first single-quoted token in each global soar_action_catalog VALUES row: (NULL, 'key',
catalog_files="$(grep -lE 'INSERT INTO soar_action_catalog' "$MIG"/*.sql || true)"
if [ -z "$catalog_files" ]; then
  echo "check-playbook-actions-cataloged: could not find any soar_action_catalog seed — expected 0036." >&2
  exit 1
fi
catalog_keys="$(grep -hoE "\(NULL, '[a-z0-9_]+'" $catalog_files | sed -E "s/.*'([a-z0-9_]+)'.*/\1/" | sort -u)"

# Playbook step actions: "action":"key" inside any seeded playbook steps JSON.
playbook_files="$(grep -lE 'INSERT INTO playbooks' "$MIG"/*.sql || true)"
if [ -z "$playbook_files" ]; then
  echo "check-playbook-actions-cataloged: no playbook seeds found (nothing to check)."
  exit 0
fi
playbook_actions="$(grep -hoE '"action":"[a-z0-9_]+"' $playbook_files | sed -E 's/.*"action":"([a-z0-9_]+)".*/\1/' | sort -u)"

missing=""
for a in $playbook_actions; do
  if ! echo "$catalog_keys" | grep -qx "$a"; then
    missing="$missing $a"
  fi
done

if [ -n "$missing" ]; then
  echo "PLAYBOOK CONTENT VIOLATION: these seeded playbook step actions are NOT in soar_action_catalog and would" >&2
  echo "fail closed to 'business_critical' (never runnable) at execution:" >&2
  for a in $missing; do echo "  - $a" >&2; done
  echo "" >&2
  echo "Fix: seed the missing action_key(s) in soar_action_catalog (with the correct §9.5 risk_class + executor +" >&2
  echo "connector_key) before referencing them in a playbook, OR correct the action name in the playbook step." >&2
  exit 1
fi

echo "check-playbook-actions-cataloged: OK — every seeded playbook action resolves to a catalog action_key."
