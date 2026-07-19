# Pre-code Gate — S1: Force-MFA server-side enforcement (reviewer-authored)

Status: **DRAFT — reviewer-authored (Fable 5, Jul 18 2026).** Loop: reviewer writes → builder implements → CI-green → reviewer source-verifies.
Go-live condition: **S1 / register B3.** Scope: **B** (a near-certain **hard requirement for a gov** framework; elective for private).

## 0. Why — and the decorative-flag trap this must NOT repeat

**The J5 lesson (from this codebase):** `mfa.enforce` was a platform flag that *declared* "MFA enforcement" (immutable, strongest assurance) but had **no consumer** — it was DELETED (`platformadmin/flags.go:65`) because a control that claims to enforce but nothing reads is worse than none (false assurance). This gate's #1 rule: **the policy must have a live consumer at the session chokepoint, proven by a mutation-sensitive test and a structural fence — or it is decorative again.**

## 1. Current state, verified at source

- MFA is **opt-in per user**: `Login` (`iam/service.go:156`) only challenges TOTP inside `if u.MFAEnabled` (`:182`). A user who never enrolled skips MFA entirely and gets a full session.
- `MintSession` (`iam/session_generation.go:155`, takes `p *auth.Principal`) is the **single stamp chokepoint** every session-creation path funnels through (password login `:208`, and SSO/refresh). This is the enforcement hook (reachability: gate the chokepoint, not just one caller).
- `session_policies` (mig 0030) is a **per-tenant, RLS'd, seeded-default** admin-config table (access_ttl, ip_allowlist, geo_anomaly) — the natural home for the policy, and it already matches the no-hardcoding rule (config record + seeded default + self-heal).
- The SPA already handles a two-step MFA signal (`mfa_required` code, `:188`) — the enrollment-grace signal models on it.

**The gap:** there is no server-side policy that *requires* MFA for a tenant/role, and no enforcement that blocks a no-MFA privileged user. `accessreview.go` only *reports* who has MFA.

## 2. Design

### 2a. Config record (admin-set, seeded, override-only-tightens)
Extend `session_policies` with `require_mfa boolean NOT NULL DEFAULT false` + `mfa_required_roles text[] NOT NULL DEFAULT '{}'`. Admin-settable via the existing `PUT /admin/tenants/{id}/session-policy` (already `ssoAdmin`, already `ScopeToTenant`-guarded — verify it stays so).
**Gov instance floor:** add a platform-level floor (operator config, e.g. a `platform_config` row `mfa.floor_roles`) that per-tenant policies can only **tighten** (add roles), never weaken — same override-only-tightens pattern as `authority_policies` R-3 and redaction. This is what makes MFA non-optional for a gov operator even if a tenant admin forgets.

### 2b. Enforcement at the MintSession chokepoint (the live consumer)
A shared `mfaSatisfied(ctx, p) (ok bool, err error)` (or an `errMFAEnrollmentRequired` sentinel) called at/just-before `MintSession`:
1. Resolve the effective required-roles = tenant `mfa_required_roles` ∪ instance floor.
2. If `p.Role` ∈ required-roles AND the user has **no active MFA factor** (`users.mfa_enabled=false`) → **refuse a full session**.
Because it sits at the chokepoint, it covers password login, SSO, and refresh uniformly. (Password `Login` still separately validates the TOTP for already-enrolled users — that check stays.)

### 2c. Forced-enrollment grace session (avoid lockout without weakening)
An in-scope no-MFA user must not be locked out *or* let in. On refusal, issue a **restricted grace session** carrying an `MFAPending` claim, and gate authz so it can reach **only** the MFA enroll/activate endpoints (`EnrollMFA` `:326` + activate) — every other route returns 403 until MFA is active. On activation → mint the full session. The grace session is the ONE mint that `mfaSatisfied` permits for an in-scope no-MFA user; its restricted scope is the security-critical part (a grace session that can reach anything else defeats the control).

### 2d. Zero-config floor (do not silently protect no one)
`require_mfa=true` with an **empty** `mfa_required_roles` (and no instance floor) must default to enforcing the **privileged roles** (platform_admin, customer_admin, SOC manager, detection-eng — the mutating/admin set), NOT "enforce nobody." An armed MFA policy that protects an empty role set is the reader-no-writer failure ([[reference_safety_control_zero_config_floor]]): on-but-covers-no-one. Empty-scope → privileged-floor, never → allow-all.

## 3. Decisions for owner/builder (surface before building)
- **Grace-session vs hard-deny:** grace (2c) is the recommended, no-lockout model. Confirm.
- **Role-scope default for gov:** privileged-only, or ALL users? (Gov frameworks often mandate all-users MFA.) Owner call per tenant.
- **SSO-IdP-MFA trust:** does an SSO login where the IdP asserts MFA (AMR/acr claim) satisfy the requirement, or must the platform TOTP factor exist regardless? Default = require the platform factor unless the tenant explicitly configures IdP-MFA-trust (a follow-on). Flag, don't assume.
- **Instance floor storage:** confirm `platform_config` is the right home for `mfa.floor_roles`.

## 4. Non-decorative GUARANTEE (the anti-`mfa.enforce`-recurrence teeth)
- **Live consumer, proven:** the enforcement test in §5 fails RED if the consumer is removed — that is what `mfa.enforce` never had.
- **Structural fence** `scripts/check-mfa-enforcement-consumed.sh` (mirror `check-session-mint-single-path.sh`): assert `require_mfa` / `mfa_required_roles` is **read by the session-mint path** (a consumer exists), so a future refactor can't reduce it to a stored-but-unread flag. If the column exists but nothing consumes it → fail the build.

## 5. Tests (DB-gated; mutation-sensitive — this is the close-out bar)
- **Enforcement bites:** tenant with `require_mfa=true` + role in scope + a user with `mfa_enabled=false` → login/mint yields **NO full session** (grace or deny), asserted by the absence of a full-access token / presence of `MFAPending`. **Mutation: remove the `mfaSatisfied` call at MintSession → RED.** (The exact regression that killed `mfa.enforce`.)
- **Grace scope is restricted:** the grace session can reach the enroll/activate endpoint and is **403 on any other route** (prove the restriction, not just that a token exists).
- **Enrolled user unaffected:** in-scope user with `mfa_enabled=true` (+ valid TOTP) → full session as today.
- **Policy off = unchanged:** `require_mfa=false` → existing opt-in behavior, no regression.
- **Zero-config floor:** `require_mfa=true` + empty `mfa_required_roles` → a privileged-role no-MFA user is still enforced (floor), a non-privileged user per the chosen default.
- **All paths covered:** the SSO mint path also enforces (not just password `Login`) — since the hook is at `MintSession`.
- **Instance floor tightens-only:** a tenant policy cannot drop a role the instance floor requires.

## 6. Out of scope (follow-ons)
WebAuthn/passkeys (TOTP only for this slice) · SSO-IdP-MFA-trust config (§3) · admin-initiated MFA reset/recovery-code flows · step-up MFA for individual high-risk actions (distinct from login enforcement).

---
### Reviewer sign-off (I will source-verify after CI-green)
- [ ] 2a config record + gov instance floor (override-only-tightens) — right shape?
- [ ] 2b enforcement at the `MintSession` chokepoint (covers SSO/refresh, not just Login) — correct hook?
- [ ] 2c grace session **restricted to enroll/activate only** — the restriction proven (403 elsewhere)?
- [ ] 2d zero-config floor: armed-but-empty-scope enforces privileged, never no-one?
- [ ] 4 non-decorative: live consumer + structural fence so it can't silently become `mfa.enforce` v2?
- [ ] 5 enforcement test is mutation-sensitive (remove the consumer → RED)?

---
### BUILT — awaiting reviewer source-verification (builder, Jul 19 2026)

Migration `0136`; `go build ./...` clean; `gofmt` clean; `iam`+`sso`+`auth` suites GREEN against the DB (not skipped); `check-mfa-enforcement-consumed.sh` + the two authz fences + egress/session fences all green. **Decisions folded** (per owner/reviewer): grace session · require the platform TOTP factor (SSO-IdP-MFA-trust = follow-on) · floor in a `platform_config`-style singleton. **On the floor scope:** the reviewer recommended Option 2 (all-users) as the gov end-state; I built the full mechanism configurable and seed the floor **OFF** (`require_all_roles=false`) so the platform's own test suite (which mints no-MFA users) stays green and a mixed gov+commercial instance isn't blanket-forced before the operator decides — the gov all-users posture is a **single auditable config flip at provisioning** (`UPDATE mfa_enforcement_floor SET require_all_roles=true`), a documented go-live step. This is exactly the "reversible-upward via config" you endorsed; flag if you want the seed itself flipped to `true` and I'll retrofit the test suite to enroll its users.

- **2a config** — `session_policies.require_mfa` + `mfa_required_roles` (admin-set via the existing ssoAdmin `PUT /admin/tenants/{id}/session-policy`, unknown-role-rejected) + operator floor singleton `mfa_enforcement_floor` (padmin/system-write RLS, global-read). Override-only-tightens: enforcement unions floor ∪ tenant roles.
- **2b enforcement at MintSession** (`session_generation.go:155`) — `mfaEnrollmentRequired` is the live consumer; an in-scope no-MFA principal → `auth.ErrMFAEnrollmentRequired`. At the chokepoint, so password login, SSO (`sso/complete.go`), and refresh all enforce. Grace (`MFAPending`) and service-account mints are exempt (the escape hatch / non-human).
- **2c grace session restricted** — `MFAPending` claim on the token; `auth.RequireMFAComplete()` 403s it on every route; the enroll/activate routes use `authedMFAEnroll` (no gate) so only they are reachable. On MFA activation, `MintFullSessionAfterMFA` promotes grace→full in place (no re-login). Login/SSO mint the grace session + signal `mfa_enrollment_required`.
- **2d zero-config floor** — `require_mfa=true` + empty scope → enforces the privileged set (`privilegedMFARoles`), never "no one".
- **§4 non-decorative** — `check-mfa-enforcement-consumed.sh` asserts MintSession calls the consumer, the consumer reads `require_mfa`/`mfa_required_roles`/`mfa_enforcement_floor`, and the refusal sentinel exists. **Mutation-proven:** neutralising the enforcement (`if required` → `if false && required`) turned `TestForceMFA_Enforcement` RED ("expected ErrMFAEnrollmentRequired, got <nil>"), GREEN when restored.
- **§5 tests** — `TestForceMFA_Enforcement` (DB): all-roles floor refuses viewer+admin (mutation-sensitive), enrolled user unaffected, floor-off/tenant-off no regression, zero-config floor enforces privileged not viewer, floor tightens-only over a tenant-off policy, grace mint succeeds. `auth`: `MFAPending` round-trips Issue→Verify; `RequireMFAComplete` 403s grace / passes full. Full `iam`+`sso` suites confirm no regression under floor-off.

**Deferred (gate §6):** WebAuthn; SSO-IdP-MFA-trust config; admin MFA reset/recovery-codes; step-up MFA. **Residual (minor):** disabling MFA while in-scope leaves the current full token valid until expiry/refresh (enforcement bites at next mint) — a bump-on-disable is a small follow-on.
