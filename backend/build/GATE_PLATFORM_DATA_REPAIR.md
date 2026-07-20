# Pre-code Gate — Platform data-repair (operator mutation tools) — reviewer-authored

Status: **CLEARED TO BUILD — reviewer-authored (Fable 5, Jul 20 2026), decisions LOCKED.** Loop: reviewer writes → builder implements → CI-green → reviewer source-verifies.
Origin: §6.18 platform-admin — the **mutating** half deferred from slice B (`a52dff2`, read-only). Concrete scope (builder): requeue stuck jobs · clear stale locks · purge orphans.
Scope: **the single most dangerous surface on the platform** — a mutation that, done wrong, bypasses every domain invariant (RLS, four-eyes, authority, audit-immutability, retention). Falsification bar: "what turns a repair tool into a God-mode write / an audit-history rewrite / a second door around a guarded surface."

## 0. The governing principle
**Data-repair is a REGISTRY of NAMED, BOUNDED, dry-run-first, audited repair operations — NEVER a generic arbitrary-write or arbitrary-SQL primitive.** The danger is not any single repair; it is a tool general enough that it can touch anything. Every property below exists to keep the blast radius of "repair" equal to the specific, reviewed operation — never wider.

## 1. Current state, verified at source
- Slice B is read-only (`platform_read.go`); data-repair is explicitly *"NOT here"*.
- **Immutable / append-only tables data-repair must NEVER delete or rewrite** (`REVOKE DELETE` at grant): `audit_log` (0017), evidence packs (0024), tenant-governance (0028), compliance (0042), detection-lifecycle (0049), suppression (0051), the retention/billing/report/war-room ledgers, `ai_response_proposals`. Rewriting any of these destroys forensic/regulatory integrity.
- **Single-door guarded surfaces data-repair must NEVER become a second door to** (each has a `check-*.sh` fence today): `authority_policies` (authority-single-path), `mfa_enforcement_floor` (mfa-enforcement-consumed), session mint (session-mint-single-path), retention window (retention-window-single-path), crypto/KMS (kms-provider-boundary), grants/RBAC, `jurisdiction_delete_armed`. A repair that writes any of these bypasses its guard — forbidden.

## 2. Design — LOCKED

### 2a. Named operations, not a primitive
Each repair is a **distinct, enumerated operation** with typed parameters and its own validation — e.g. `RequeueStuckJob(jobID)`, `ClearStaleLock(lockKey)`, `PurgeOrphan(kind, id)`. **No** endpoint that takes a table name, a column, a WHERE clause, or SQL from the caller. **No** dynamically-built SQL from input. The set of repairs is a closed, reviewed list; adding one is a code change that re-enters this gate.

### 2b. Bounded target surface (the allowlist)
Repairs may touch ONLY the **operational-plumbing** tables their operation names (the outbox/queue, lock/lease rows, and the specific orphan kind). A repair may **never** write:
- any immutable/append-only table (§1) — structurally blocked;
- any business-record content (incidents, alerts, evidence, cases, detections) — repair fixes *plumbing*, not investigations;
- any guarded security surface (§1) — those have their own doors.
Enforced by an **allowlist in code + a fence** (2f), not by convention.

### 2c. Dry-run first, fail-safe default
Every repair **previews** what it would change — the exact affected ids + before-state — and changes nothing unless an explicit `apply=true` (or a two-call preview→confirm). Default is dry-run. A repair whose preview shows **more than a bounded row count** (e.g. >N) refuses to apply without an explicit high-count acknowledgment (a repair expected to touch 1 row that finds 10,000 is a red flag, not a bulk job).

### 2d. Four-eyes for destructive repairs + tiered authority
- **Destructive/irreversible repairs** (purge/delete anything) require a **second senior approver** (reuse the report-approval / SOAR four-eyes machinery — creator ≠ approver). Reversible requeue/unlock may be single-actor but still audited.
- **platform_admin only**, and the destructive tier requires **break-glass / elevated PAM grant** (reuse the existing PAM/break-glass path) — not every padmin can purge. Route-gated `padmin` + in-service tier check.

### 2e. Immutable audit + reversibility snapshot
- **Every repair — dry-run AND apply — writes an immutable audit row**: actor, operation, typed params, affected ids, before-state (serialized), outcome, timestamp. The repair audit is itself append-only (a repair that isn't fully audited is an untraceable mutation — the whole point of the tool is a *traceable* fix).
- Before a destructive repair, **capture the prior state** (the purged rows / the changed values) into the audit or a repair-ledger so the action is reconstructable. Irreversible operations carry the highest bar (four-eyes + break-glass + explicit ack).

### 2f. Fail-closed
Unknown operation / unrecognized params / target outside the allowlist / preview-count over bound without ack / missing approver on a destructive op → **refuse**. Never a partial or best-effort mutation.

## 3. Non-decorative GUARANTEE (the teeth)
`scripts/check-datarepair-bounded.sh` (blocking in CI, mirrors the sibling fences):
- **No arbitrary SQL:** the data-repair package builds no dynamic SQL from input — no `fmt.Sprintf` into a query, no caller-supplied table/column/where. (grep for string-built queries / a table-name parameter → fail.)
- **Allowlist honored:** the only tables the repair package writes (`UPDATE/DELETE/INSERT`) are the operational-plumbing allowlist; any write to an immutable table (§1) or a guarded surface (§1) from `internal/platformadmin/**repair**` → fail, naming the file:line.
- **Chokepoint:** every repair routes through the one dry-run+audit function (no repair mutates without an audit row) — assert the mutate path and the audit call are co-located, like `check-connector-decrypt-audit.sh`.
Mutation-proven: inject a repair that writes `audit_log` (or `authority_policies`, or takes a table-name param) → RED; remove → GREEN. If the repair package is absent the check must fail, not silently pass.

## 4. Falsification tests (each mutation-sensitive)
1. **No arbitrary write:** there is no code path that mutates a caller-named table/column (fence #1 + a test that the API surface is the enumerated ops only).
2. **Immutable untouched:** a repair cannot delete/rewrite `audit_log`/evidence/a ledger — attempt (in a test/fence) → refused/absent.
3. **No second door:** a repair cannot write `authority_policies` / `mfa_enforcement_floor` / crypto config / a grant — fence + test.
4. **Dry-run default:** calling a repair without `apply` changes nothing and returns the preview; mutation only on explicit apply.
5. **Row-count bound:** a repair whose preview exceeds the bound refuses without an explicit ack.
6. **Four-eyes on destructive:** a purge/delete repair by a single actor is blocked; a distinct senior approver is required (creator ≠ approver).
7. **Break-glass tier:** the destructive tier requires the elevated PAM grant, not plain padmin.
8. **Audit completeness:** every repair (dry-run + apply) writes an immutable audit row with before-state; removing the audit call → the fence/test goes RED.

## 5. Out of scope (follow-ons)
Scheduled/automatic self-healing repairs (first slice = operator-initiated only) · a generic "admin SQL console" (explicitly NEVER — it is the anti-pattern this gate exists to forbid) · business-record correction workflows (incident/case edits have their own domain paths, not data-repair) · bulk data migration (that is a migration, reviewed as one).

---
### Reviewer sign-off (I source-verify after CI-green)
- [ ] 2a — repairs are enumerated named operations; no table/column/SQL from input; no dynamic query (fence #1, test #1).
- [ ] 2b — write allowlist honored; immutable tables + guarded surfaces structurally unreachable (fence, tests #2, #3).
- [ ] 2c — dry-run default; row-count bound with explicit-ack (tests #4, #5).
- [ ] 2d — four-eyes on destructive (creator ≠ approver); destructive tier = break-glass/PAM, route padmin (tests #6, #7).
- [ ] 2e — every repair immutably audited with before-state; destructive captures reversibility snapshot (test #8).
- [ ] 3 — `check-datarepair-bounded.sh` blocking in CI, mutation-proven; fails if the repair package is absent.
