# Pre-code GATE REQUEST — §6.14 B3: jurisdictional retention → retention-delete

Status: **BUILD DEFERRED, awaiting reviewer pre-code gate.** Per owner directive on #178: "when you wire the
jurisdictional-retention → retention-delete path, pause for the reviewer — data-destruction machinery gets a look."
B1 (authoring API) + B2 (audit-readiness pack) shipped freely; this is the one piece that touches the delete path.

## Why this needs a gate (not built freely)

It wires a NEW config axis into the ONLY code path that DELETES customer telemetry — `retention_delete_raw` /
`retention_delete_events` (mig 0116, SECURITY DEFINER, evidence-immutability-bypass-for-this-path-only) + the
`retention_deletion_ledger` (mig 0119). Any change that can make deletion **more aggressive** (a shorter effective
window) or reach **more data** is exactly the falsification surface. It must not become a path to over-deletion or a
legal-hold bypass.

## Current retention model (verified at source, mig 0116)

- `retention_policy` — per-tenant (NULL=global), `enabled DEFAULT false` (dry-run/report-only SAFE default),
  `window_days` OPTIONAL **tighten-only** override: effective window = `min(window_days, entitlement retention_days)`
  (a tenant may only ask to keep telemetry for LESS, never more than its entitlement).
- Deletes ONLY raw telemetry (`raw_events` + payload blob, `events`); NEVER alerts/incidents/evidence/audit.
- `retention_delete_*` REFUSE when `tenants.legal_hold` is true (defense-in-depth over the Go check).
- Append-only `retention_sweep_log` records every sweep incl. dry-runs.

## The design to review (proposed, NOT built)

**Problem:** a sovereign jurisdiction imposes a retention rule that is data-driven, not entitlement-driven — and it can
point in EITHER direction, which is the crux:
- a **maximum** (data-protection "delete personal data after N days" → a CEILING that SHORTENS the window → more deletion), or
- a **minimum** (sector "retain security logs for at least M days" → a FLOOR that LENGTHENS retention → less deletion).

**Proposed model (single reachable unit — no armed-but-dead config):**
1. `jurisdiction_retention` config: `{jurisdiction_key, min_retain_days (floor), max_retain_days (ceiling)}`, seeded
   global defaults, padmin-managed (a jurisdiction is operator/sovereign-level, not tenant-self-service).
2. `tenants.jurisdiction` (or reuse an existing sector/country field) selects the tenant's jurisdiction.
3. Effective window reconciliation at the sweep — the ORDERING is the whole security question, proposed as:
   `effective = clamp(min(tenant window_days, entitlement), floor=jurisdiction.min_retain_days, ceiling=jurisdiction.max_retain_days)`
   with **two hard invariants for the reviewer to falsify:**
   - **legal_hold ALWAYS wins** — never deletes held data regardless of any jurisdiction ceiling (the SD functions
     already refuse on hold; the Go path must too, and a jurisdiction ceiling must not be a route around it).
   - **a jurisdiction FLOOR beats an entitlement/tenant ceiling** — i.e. a mandated-retention minimum can only make the
     window LONGER (keep more), never shorten below the sector minimum, even if a tenant asked for less. Conversely a
     jurisdiction CEILING (data-protection max) can shorten — this is the ONE direction where deletion becomes more
     aggressive, and it must stay dry-run-default + audited + laddered behind an explicit enable.
4. Keep `enabled DEFAULT false` (dry-run) — jurisdictional deletion never silently activates.

## What I want the reviewer to gate before I build

- Is the clamp ordering correct (floor-beats-ceiling, legal-hold-supreme), or should a mandated-delete ceiling ever
  override a retention floor? (I believe floor wins; confirm.)
- Should jurisdiction be padmin-only (operator sets the sovereign regime), never tenant-self-service? (I believe yes.)
- Is a per-jurisdiction CEILING that shortens the window acceptable at all pre-KMS, or does mandated-DELETE wait until
  production KMS + the retention-delete soak? (It increases deletion aggressiveness — may belong behind the go-live line.)
- Fence: a structural check that the effective-window function is the SOLE producer feeding `retention_delete_*`, and
  that legal_hold short-circuits it (mirrors the SOAR single-decision-point + zero-config-floor patterns).

On your gate I'll build it as one reachable unit (config + reconciliation + sweep wiring + tests: legal-hold-supreme,
floor-beats-ceiling, dry-run-default, tighten-only-vs-entitlement preserved), mutation-sensitive.
