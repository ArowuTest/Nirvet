# Pre-code Gate — Structural authz-chokepoint fences (reviewer-originated hardening)

Status: **DRAFT — reviewer-authored (Fable 5, Jul 18 2026).** Loop: reviewer writes → builder implements → CI-green → reviewer source-verifies.
Origin: parallel-door/surface sweep prompted by another project's reviewer post-mortem (a legacy config path that
became an authz bypass when the security model changed, because reviews audited diffs not the whole current surface).

## 0. Why — the failure mode this makes structurally impossible

Nirvet's authz is **per-route middleware wrappers** applied by hand at each `mux.Handle` in `cmd/api/main.go`.
That is correct today (swept Jul 18 — all config mutations guarded, no unguarded door), but it is **not
recurrence-proof**: a future route added without a wrapper, or a future direct DB write to a sensitive config
table, is a silent bypass that no test would catch. This is exactly the other project's miss. Nirvet already
solves this class elsewhere with structural `check-*.sh` fences (`check-session-mint-single-path.sh`,
`check-ai-egress-redaction.sh`, `check-security-definer-revoke.sh`). This gate applies the same pattern to authz.

**Verified-at-source facts this gate locks in (do not re-derive — but re-confirm before building):**
- Authority-to-act is the crown-jewel config (it gates autonomous containment via `soar.Allowed(mode,risk)`).
  Both mutation doors — `POST /soar/authority` (padmin) and `PUT /admin/tenants/{id}/authority-policies`
  (ssoAdmin) — funnel through ONE usecase, `tenant.Service.SetAuthorityPolicy` (`governance.go:493`), whose
  guards enforce: permissive modes (`pre_authorized`/`contractual_auto`) require `platform_admin` (R-3), and the
  `*` catch-all may only be restrictive (L3). `SetCatchAllAuthority` delegates to it. The ONLY other writer is a
  safe default-`observe` seed (`governance.go:190`).
- The authz wrapper vocabulary is a closed set: `authed, provider, aiProvider, padmin, detEng, oversight,
  soarApprover, soarAuthor, senior, manager, ssoAdmin, customerRead, customerWrite` (+ the `interactive` base).

## 1. Fence A — authority-mutation single-door (`scripts/check-authority-single-path.sh`)

Mirror `check-session-mint-single-path.sh`. **Assert every `INSERT INTO authority_policies` / `UPDATE
authority_policies` in non-test Go lives ONLY in `internal/tenant/governance.go`** (the guarded usecase + the
seed). Any write elsewhere = a path that bypasses the R-3/L3 tighten-only guard → fail the build with a message
naming the offending file:line. This makes "a customer-reachable code path sets a permissive authority mode
without the platform_admin check" structurally unrepresentable, not merely absent today.

Optionally tighten further: assert the two legitimate writes both sit inside functions whose body contains the
R-3 guard token (`RolePlatformAdmin`) or are the const-`'observe'` seed — so even a new writer *inside*
governance.go can't skip the guard. (Nice-to-have; the file-scope assertion is the required minimum.)

## 2. Fence B — every mutating route is guarded (`scripts/check-route-authz-coverage.sh`)

Parse `cmd/api/main.go` for every `mux.Handle("(POST|PUT|PATCH|DELETE) ...")`. For each, assert the handler
expression is wrapped in one of the closed-set authz guards above, **OR** the route path is on an explicit,
in-script **PUBLIC_ALLOWLIST** with a one-line justification each. The allowlist is the complete set of
intentionally-non-session routes (verified Jul 18):
- `POST /auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/invitations/accept`,
  `/auth/password-reset/confirm`, `/auth/sso/saml/acs` — pre-auth, establish the session (rate-limited).
- `POST /ingest/webhook/{id}` — authenticated by the per-connector webhook key, not a session.
- `POST /soar/approve-link` — authenticated by a single-use signed HMAC link token, not a session.

Any mutating route that is neither guard-wrapped nor on the allowlist → fail, naming the route. A new sensitive
route added without a wrapper now breaks CI instead of silently shipping a bypass. **The allowlist itself is the
audit surface** — adding to it is a conscious, reviewed act (the whole point).

Keep it structural (grep/awk over `main.go`, like the sibling fences) — not a runtime check.

## 3. Wire both into CI

Add both scripts to the same CI step that runs the existing `check-*.sh` fences (see how
`check-session-mint-single-path.sh` is invoked). They must be blocking (non-zero exits fail the build), matching
the others.

## 4. Bundled LOW cleanups (fold in — they are the sweep's residuals)
- **Stale enum string:** `internal/tenant/governance.go:479` error message says `"invalid mode:
  observe|approval|pre_authorized|emergency"` — `emergency` was renamed to `contractual_auto` in mig 0127 and is
  no longer a valid mode. Fix the message to `...|contractual_auto`. (It nearly produced a false finding in the
  sweep — a stale name that reads as a coverage gap.)
- **/metrics posture:** `GET /metrics` is intentionally unauthenticated for the scrape collector. Confirm (a) it
  is network-restricted in the deploy (not publicly reachable), and (b) no metric carries a tenant-identifying
  label (a cross-tenant enumeration leak). Sweep found no tenant labels; this is a confirm-at-deploy item.

## 5. Out of scope
The authz model itself is unchanged — this gate adds structural *fences* around the existing, correct model; it
does not move any route or alter any guard. No new runtime behavior.

---
### Reviewer sign-off (I will source-verify after CI-green)
- [ ] Fence A fails when an `authority_policies` write is added outside `governance.go` (add a temporary offending
      write in a branch, confirm RED, remove).
- [ ] Fence B fails when a mutating route is added without a wrapper and not on the allowlist (same mutation proof).
- [ ] The PUBLIC_ALLOWLIST contains exactly the 4 justified entries above — nothing more.
- [ ] Both fences are blocking in CI alongside the sibling `check-*.sh`.
- [ ] LOW cleanups folded (enum string; /metrics posture confirmed).

---
### BUILT — awaiting reviewer source-verification (builder, Jul 18 2026)

Both fences GREEN on the clean tree; **both mutation-proven RED→GREEN** (a fence that can't fail proves nothing):

**Fence A — `scripts/check-authority-single-path.sh`** (models `check-session-mint-single-path.sh`). Asserts `INSERT INTO|UPDATE authority_policies` in non-test Go lives ONLY in `internal/tenant/governance.go`. Grounded at source: the two writes are the guarded usecase (`governance.go:498`) and the safe `'observe'` seed (`governance.go:190`). **Mutation proof:** added `UPDATE authority_policies …` in `internal/soar/` → RED (named the file:line); removed → GREEN.

**Fence B — `scripts/check-route-authz-coverage.sh`.** Parses every `mux.Handle("(POST|PUT|PATCH|DELETE) …", <expr>)` in `cmd/api/main.go`; the handler's leading identifier must be in the closed guard set (`authed provider aiProvider padmin detEng oversight soarApprover soarAuthor senior manager ssoAdmin customerRead customerWrite`) OR the path must be on the 8-entry `PUBLIC_ALLOWLIST`. Grounded: all **175** mutating routes parse (tally sums exactly); 167 use closed-set guards, 8 use `httpx.Chain` and those 8 paths are **exactly** the allowlist (the 6 pre-auth `/auth/*`, `/ingest/webhook/{id}` by key, `/soar/approve-link` by HMAC) — nothing more. **Mutation proofs:** (1) added `POST /pwn/backdoor` wrapped in bare `http.HandlerFunc` → RED (named the route); (2) removed `/auth/refresh` from the allowlist while the route exists → RED (proves the allowlist is load-bearing, not decorative); both restored → GREEN.

**CI wiring:** both added to `.github/workflows/ci.yml` as blocking guard steps beside the sibling `check-*.sh` (after the AI-egress/eval fences).

**LOW cleanups:** (1) `governance.go:479` error message `…|emergency` → `…|contractual_auto` (the mig-0127 rename). (2) `/metrics` posture: registered at `main.go:569` via `promhttp.Handler()` (Go process/runtime metrics + the platform's own counters); a source grep for tenant-identifying labels in metric definitions found **none** (no cross-tenant enumeration surface). Network-restriction of the scrape endpoint remains a **deploy-config** item (not code) — flagged for the Render/ingress config, not changed here.

**No authz-model change** — these are fences around the existing, correct model; no route moved, no guard altered.
