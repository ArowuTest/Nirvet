#!/usr/bin/env bash
#
# check-ai-tool-registry.sh — the CI teeth behind GATE_COPILOT_COMPLETION_I2_AGENTIC.md §3. The copilot's agentic
# tool set (internal/ai) must be a CLOSED, READ-ONLY allowlist. Read agency ≠ execute agency: a future tool that
# writes, mutates, executes a response, calls a connector, or runs a raw query cannot be added to the registry without
# tripping CI (and re-entering the gate). Structural grep over internal/ai — no build/cluster needed. Run from backend/.
set -euo pipefail

cd "$(dirname "$0")/.."
fail=0

# The KNOWN read-only allowlist. Adding a member is a gate decision (edit here + the gate); every one must be a
# read-only RunHunt/verified-reader-backed tool. run_hunt is this slice; pivot_entity/get_timeline are the same family.
ALLOWED='run_hunt|pivot_entity|get_timeline'

# 1. Every agentic tool CONSTANT value must be in the allowlist (a new tool name outside it → RED).
consts="$(grep -rhoE 'agentTool[A-Za-z]+[[:space:]]*=[[:space:]]*"[a-z_]+"' internal/ai --include='*.go' 2>/dev/null | sed -E 's/.*"([a-z_]+)".*/\1/' | sort -u || true)"
for t in $consts; do
  if ! printf '%s' "$t" | grep -qE "^($ALLOWED)$"; then
    echo "❌ AI-TOOL-REGISTRY VIOLATION: agentic tool '$t' is not in the read-only allowlist ($ALLOWED)." >&2
    echo "   A copilot tool that writes/mutates/executes must re-enter GATE_COPILOT_COMPLETION_I2_AGENTIC.md." >&2
    fail=1
  fi
done

# 2. Belt-and-suspenders: no destructive-looking tool name may be declared, even if someone bypassed the const naming.
bad="$(grep -rnE 'agentTool[A-Za-z]*[[:space:]]*=[[:space:]]*"(isolate|disable|block|delete|remove|create|update|write|execute|run_playbook|contain|quarantine|kill|reset|rotate|approve|accept)[a-z_]*"' internal/ai --include='*.go' 2>/dev/null || true)"
if [ -n "$bad" ]; then
  echo "❌ AI-TOOL-REGISTRY VIOLATION: a destructive/mutating tool name is declared in the agentic registry:" >&2
  echo "$bad" | sed 's/^/  - /' >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "check-ai-tool-registry: OK — the copilot agentic tool set is a closed read-only allowlist ($ALLOWED); no write/execute tool."
