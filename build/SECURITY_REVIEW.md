# Security Review — Findings & Status (Jul 2026)

Honest record of the internal security review and what has actually been fixed. This
is the single source of truth for security posture; if a claim here conflicts with an
older "done" label elsewhere, this file wins. A formal expert security-architect review
is still required **pre-go-live** (build-phase sign-off only — see memory
`feedback_nirvet_signoff`).

## Fixed (committed, tested)

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
- **asset inventory (§6.15)** — slice 1 DONE (Jul 2026): tenant-scoped asset registry
  (host/user/service/cloud) with business criticality, matched to cases by ref and
  surfaced in the evidence pack (migration 0022, `internal/asset`). Follow-on:
  vulnerability + exposure records, and criticality feeding incident severity/SLA.

See `MODULE_DEFINITION_OF_DONE.md` for the per-module test/RBAC/observability matrix.
