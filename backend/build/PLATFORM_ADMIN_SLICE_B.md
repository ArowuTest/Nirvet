# §6.18 #175 Platform-Admin slice B — build note

Survey found most of slice B already built. This increment ships the genuine **read-only** gaps and flags the one
**mutation** surface for its own gate.

## Built (read-only, non-gated)
- **`GET /admin/maintenance-windows`** — the LIST read of maintenance windows. `CreateWindow` existed but windows
  could never be read back (a create-without-read asymmetry). Each window carries a server-computed `Active` state.
- **`GET /admin/settings`** — a **non-secret** platform settings snapshot for the admin settings screen: environment,
  instance (`single-sovereign`), crypto provider + require-KMS, AI model, event/queue/blob backends, cache mode,
  plus dynamic flag/maintenance counts. **Never a secret** (no JWT secret, master key, provider token, API key, DSN).

## Already done (verified at source — not rebuilt)
- **Health dashboard** — `internal/platformhealth` is complete and deliberately honest (live dep liveness + Go runtime
  + honest "configured" for soft deps; never fabricates a fleet). `GET /admin/health` already serves it.

## Deferred to its own pre-code gate (NOT built here)
- **Data-repair** — operator tools that would MUTATE platform/operational state (requeue stuck jobs, clear stale
  locks, purge orphans). This is a security-sensitive write/destructive-adjacent surface; per the gated-build
  discipline it needs a reviewer pre-code gate before implementation. Flagged, not started.

## Noted (optional, overlaps existing)
- **Content-library** — the operator's reusable content (detection rules, playbooks, report types, compliance
  frameworks) is already surfaced by the existing detection catalog, playbook authoring, report policy, and
  compliance authoring endpoints. A single read AGGREGATE over those could be added if the settings/content screen
  wants one call, but it would be redundant with what exists — offered, not built speculatively.

Tests: DB-gated `TestListWindows_ActiveComputed` (active vs ended). openapi coverage green; build/vet clean.
