# Security Review — Findings & Status (Jul 2026)

Honest record of the internal security review and what has actually been fixed. This
is the single source of truth for security posture; if a claim here conflicts with an
older "done" label elsewhere, this file wins. A formal expert security-architect review
is still required **pre-go-live** (build-phase sign-off only — see memory
`feedback_nirvet_signoff`).

## Round 2 (Jul 2026) — all findings fixed, no deferrals

Second external review (to HEAD 86afcbd) found no new Critical and confirmed tenant
isolation airtight. Owner directive: fix everything now for a clean next pass. All done,
each gated + tested + green on both backends:

| Finding | Fix | Commit |
|---|---|---|
| H-E background loops no recover() | `platform/safe.Do` wraps poller/reconciler/SLA-sweeper ticks | `ca7386e` |
| H-C correlation promotion non-atomic → dup/unbounded incidents | claim-then-create (ClaimForPromotion + SetIncident) | `70691f4` |
| M-C alert_count lost update | UpdateActive (SELECT … FOR UPDATE) | `70691f4` |
| M-B SLA breach TOCTOU (dup emails) | ClaimBreach before notify (exactly-once) | `70691f4` |
| H-D BFLA flat provider tier | senior + manager tiers on destructive routes | `e685caf` |
| M-D asset criticality writable by T1 | asset writes gated to manager (admin/soc_manager) | `e685caf` |
| H-A AI prompt injection unfenced | sentinel-fenced data block + system-prompt rule | `3af74ed` |
| M-F AI output not audited | persist output text + sha256 | `3af74ed` |
| H-B evidence pack tamper-evidence cosmetic | real Ed25519 signature over envelope+sections + Verify | `7b0ca80` |
| H-Res raw_events/events still mutable | REVOKE DELETE/UPDATE + column-scoped triggers (migration 0024) | `3482c69` |
| M-E entity-graph N+1 pool exhaustion | incident.GetByIDs batch | `5c8cd64` |
| M-A single-event auto-promotion spam | corroboration (≥2 alerts) before auto-promote | `5c8cd64` |
| lows: SSO role re-validate, vault key-version byte, gosec+govulncheck CI | — | `2c65037` |

## Round 3 (Jul 2026) — all findings fixed, no deferrals

Third external review (of the Round-2 fixes) confirmed "excellent remediation": no Critical
or High, tenant isolation still airtight. It raised one regression from my own Round-2 vault
fix plus a correctness/hardening punch-list. Owner directive again: fix everything now for a
clean pass. Status:

| Finding | Sev | Fix | Commit |
|---|---|---|---|
| M-NEW vault version-byte broke legacy decrypt (would orphan existing MFA/connector secrets on deploy) | Med | Decrypt falls back to the pre-version `[nonce][ct]` layout; `TestDecryptLegacyFormat` | `4c4f965` |
| L-Triage-Audit: incident-triage persisted only a char count, not the copilot output | Low | `TriageIncident` audits `auditMeta(model, text)` (full output + sha256), matching SummariseAlert | _this batch_ |
| M-D asset criticality change had no before/after audit (an escalation-suppressing edit was invisible) | Med | `Create` is actor-attributed; on a new/changed criticality it writes an `asset.criticality_set` audit entry with previous→new | _this batch_ |
| L3 regex predicate not validated at rule-create (a bad pattern silently never-matched on the hot path) | Low | `validateCondition` rejects an uncompilable regex at create (also warms the cache) | _this batch_ |
| M1 regex predicate recompiled per-event on the detection hot path | Med | package `regexCache` (sync.Map); evaluator + validation share `compileRegex` | _this batch_ |
| CI pinned gosec/govulncheck to `@latest` (non-reproducible; a release could change results/break build) | Low | pinned `govulncheck@v1.1.3`, `gosec@v2.21.4` | _this batch_ |
| M3 CEL expression could burn CPU on the hot path (no cost bound) | Med | `cel.CostLimit(100k)` per program; over-budget eval fails safe (no-match). Deterministic cost limit chosen over a wall-clock deadline so detection stays reproducible | _this batch_ |
| AI copilot routes shared the 50-rps API bucket (LLM latency + token-spend abuse) | Med | dedicated tight per-principal `ai` bucket (~1 call/2s, burst 5) on /summarise + /triage | _this batch_ |
| global detection-rule RLS: single policy let a tenant DELETE or re-home the shared global catalogue | Med | split into per-command policies (SELECT global+own; INSERT/UPDATE/DELETE own-only). Migration 0026; integration test proves a tenant can read but not delete/re-home a global rule | _this batch_ |
| SLA-breach notification silently dropped on transient notifier failure (claim-before-notify + discarded error) | Low (reliability) | durable notification outbox: claim + timeline + enqueue commit in ONE tenant tx (keeps R2 exactly-once dedupe); background dispatcher delivers with retry, dead-letters after 5 attempts (observable), never drops. Migration 0027 + SECURITY DEFINER cross-tenant drain; two integration tests (deliver + dead-letter) | _this batch_ |
| M-D asset criticality before/after audit (reliability residual) | Low | done in the correctness batch (`2599a2e`) | `2599a2e` |
| maybePromote null-incident-on-claim-failure | Low | reviewer-accepted documented anti-spam tradeoff (cluster stays `promoted`, not retried) — left as-is by design | — |

## Fixed — Round 1 (committed, tested)

| # | Severity | Finding | Fix | Commit |
|---|---|---|---|---|
| 1 | Critical | `audit_log` was mutable by the app role — the evidentiary spine could be rewritten/erased | Append-only: REVOKE UPDATE/DELETE/TRUNCATE + BEFORE UPDATE/DELETE trigger (raises for everyone). Migration 0017 | `51eb102` |
| 2 | Critical | SSO `default_role` unvalidated — a customer_admin could JIT-mint a platform_admin via their IdP | `ValidSSORole` customer-only allowlist on OIDC + SAML CreateConnection | `51eb102` |
| 3 | High | Severity defaulted to `informational` at the ingest door, BEFORE vendor mappers → severity-derivation dead code, severity-gated detections under-fired | Validate a provided severity but leave empty for the normalizer to derive | `51eb102` |
| 4 | Critical | Ingestion not atomic (blob + row + enqueue) — a crash between row-commit and enqueue lost the event silently, no recovery | `enqueued_at` marker + system-level reconciler re-enqueues from the blob (at-least-once, idempotent). Migration 0018 | `1e8e873` |
| 5 | Critical | Vault: production could boot on an ephemeral key (all connector creds + TOTP lost on restart); KMS stub failed only at runtime | config guard requires persistent key material in production; `NewKMS` fails fast at construction | `a11625d` |
| — | High | SOAR self-approval — an analyst could request AND approve their own containment | Four-eyes: `canApprove` (requester ≠ approver) + approve/reject narrowed to senior roles | `9ab93b7` |
| — | High | Ingest worker had no `recover()` — a poison event could crash the goroutine and halt ingestion for all tenants | `processGuarded` recovers, logs, routes the job to retry/dead-letter | `9ab93b7` |
| — | Med | No way to change a password; production could ship the default bootstrap password | `POST /me/password` (verifies current) + config guard rejects the default in production | `9ab93b7` |
| — | High | Login brute-force: per-IP limit keyed on spoofable left-most X-Forwarded-For; no per-account control | Trusted-proxy-depth XFF parsing + durable per-account lockout (5 fails → 15 min). Migration 0019 | `3e9b79d` |

## Deferred to pre-go-live (tracked, NOT done)

- **KMS envelope encryption** — `kmsCipher` is a scaffold; production currently uses the
  local AES-GCM cipher with a persistent master key. Real GCP KMS wrapping is a
  pre-go-live task (ADR-0004 TODO). Flagged for the expert review.
- **SAML** — signed-assertion validation is delegated to gosaml2/goxmldsig (not
  hand-rolled) with 7 fail-closed controls, but the whole SAML surface is flagged for
  expert review before go-live.
- **Audit tamper-evidence** — `audit_log` is append-only (immutable); a cryptographic
  hash-chain (each row chained to the prior) is a follow-on for tamper-*evidence* on
  top of tamper-*resistance*.
- **Seed credential rotation** — bootstrap admin + any seeded users must be rotated
  before launch (the config guard blocks the default password, but operators must set
  real values).

## Known functional gaps (not security bugs, but do not claim "done")

- **Customer-facing portal** — not built. Customer roles exist (`customer_admin`,
  `customer_viewer`) and are RBAC-gated where used, but a dedicated customer UI/surface
  is not implemented.
- **Read-side RBAC** — write paths are gated by `RequireRole`; fine-grained read
  scoping for customer viewers (what a viewer may see vs an analyst) is not fully
  enforced across all GET endpoints.
- **SLA timers** — DONE (Jul 2026): per-severity ack/resolve targets, due-times stamped
  at creation, acknowledged_at on first ownership, derived ack/resolve breach flags
  (`internal/incident/sla.go`, migration 0020). Proactive **breach alerting** is now
  also done: a background sweeper (StartSLASweeper, migration 0021 + SECURITY DEFINER
  incidents_sla_breaches) notifies + records on the timeline exactly once per breached
  deadline. Remaining: an at-risk/breach dashboard view.
- **MFA login UI** — TOTP enroll/activate/verify exist in the API and are enforced at
  login; the front-end MFA prompt is deferred pending the designer HTML.
- **threatintel** — watchlist enrichment only; no STIX/TAXII ingest (§6.10 deferred).
- **notify** — logs the notification; real channels (email/Slack/webhook) are stubs.
- **compliance** — static/reference responses, not a live control-status engine.
- **reporting** — JSON aggregates only; no scheduled/exported report artifacts.
- **evidence-pack export (§6.13)** — DONE (Jul 2026): GET /incidents/{id}/evidence-pack
  bundles the case + timeline + linked alerts + underlying events + affected assets +
  audit trail with a SHA-256 checksum manifest (tamper-evident). Follow-on: signed/PDF
  export + object-store archival of generated packs.
- **asset inventory (§6.15)** — slice 1 + 2 DONE (Jul 2026): tenant asset registry
  (criticality, matched to cases by ref, feeds incident severity/SLA) + **vulnerability &
  exposure** (`internal/vulnerability`, migration 0025): vulns mapped to assets by ref,
  exposure summary, open vulns surfaced in the evidence pack (ASSET-004/002/006/007).
  Follow-on: identity inventory (ASSET-003), auto priority-increase from exposure,
  exceptions/accepted-risk workflow, scanner-pull connectors.

See `MODULE_DEFINITION_OF_DONE.md` for the per-module test/RBAC/observability matrix.
