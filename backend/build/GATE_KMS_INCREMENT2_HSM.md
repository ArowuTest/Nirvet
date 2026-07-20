# Pre-code Gate — KMS increment 2: PKCS#11 HSM provider — reviewer-authored

Status: **CLEARED TO BUILD — reviewer-authored (Fable 5, Jul 20 2026), decisions LOCKED.** Loop: reviewer writes → builder implements → CI-green (incl. SoftHSM job) → reviewer source-verifies.
Origin: builder-requested pre-write; the highest-assurance crypto tier (hardware root of trust — FIPS 140-2/3, defence/intel/critical-infra). Builds on the verified increment-1 seam (`GATE_KMS_PROVIDER_ABSTRACTION.md`, `a692c97`).
Scope: **the crypto crown jewel's hardware tier.** Falsification bar unchanged from incr-1 — "what exposes a key, orphans a vault, or silently downgrades" — plus the HSM-specific and build-hygiene traps below.

## 0. What is already DONE (reuse, don't rebuild) — verified at source
The whole machinery is proven and increment-2-ready:
- `keyWrapper` seam (`Wrap`/`Unwrap` only); `envelopeCipher` owns DEK/AEAD/per-tenant/versioning/zeroize — a new provider is `Wrap`/`Unwrap` behind the seam, no envelope change.
- **`tagPKCS11 = 3` is already reserved** in the providerTag enum (`kms.go:53`), with a `String()` case — provider-confusion (2c) and dual-read migration work for it out of the box.
- `require-KMS`, provider-tagged ciphertext, `transitionCipher` dual-read, boot probe, DEK zeroize — all apply unchanged.
- **The boundary fence (`check-kms-provider-boundary.sh`) auto-covers a new provider file** — it greps every file declaring `) Wrap(ctx context.Context, keyName` regardless of build tags (text-based), so a tagged `pkcs11.go` is still purity-checked.
This gate is therefore the **HSM provider + its CI + the build-hygiene isolation** — not a re-architecture.

## 1. THE build-hygiene invariant (do not skip — it breaks the image if missed)
The production image is **CGO-off, static, distroless** (`backend/Dockerfile`). PKCS#11 needs **cgo**. Therefore:
- The PKCS#11 provider MUST be behind a **build tag** (`//go:build hsm`) so the **default build stays CGO-off/static** — the distroless image, and all Vault/GCP deployments, must NOT pull in cgo or a PKCS#11 lib.
- `NewFromConfig` with `provider="pkcs11"` in a **non-hsm build** must return a **clear error** ("HSM support not compiled in — build with the `hsm` tag") — never a silent fallback, never a build break.
- Only the dedicated **HSM build/deploy** (a separate image variant or the HSM CI job) compiles with `-tags hsm` + `CGO_ENABLED=1`. The static default image is unchanged.
- The boundary fence still covers the tagged file (it's text-based) — confirm it does after the file lands.

## 2. HSM provider design — LOCKED

### 2a. KEK never leaves the token (hardware — the strongest form)
- The tenant KEK is an HSM key object created/imported with **`CKA_EXTRACTABLE = false` and `CKA_SENSITIVE = true`** — it **cannot be exported**, even by a fully-compromised app process. This is the hardware upgrade over Vault's "no export path": here export is *physically refused by the token*.
- Wrap/unwrap happen **on-token** (`C_Encrypt`/`C_Decrypt` or `C_WrapKey`/`C_UnwrapKey` against the key handle). The provider **never** reads the key value (`C_GetAttributeValue` on `CKA_VALUE` is never called) and does no local AES/GCM (boundary fence enforces provider purity).
- Likely lib: `github.com/miekg/pkcs11` (cgo) or `ThalesGroup/crypto11`. Whichever — the provider surface stays `Wrap`/`Unwrap` only.

### 2b. Per-tenant key by label/handle
`keyNameFor({tenant})` resolves to a **distinct PKCS#11 key object per tenant** — found by `CKA_LABEL` (or `CKA_ID`) = the tenant key name. Per-agency separation is the whole point; a single shared token key does not satisfy it. Onboarding provisions a non-extractable key per agency (documented in the HA/DR key-ceremony runbook).

### 2c. PIN / session handling
- The HSM PIN (`C_Login`) comes from **env/secret** (`NIRVET_HSM_PIN`) — **never the DB, never logged** (mirrors the Vault token). The module path (`NIRVET_HSM_MODULE`) + slot/token label are operator infra config (like `VAULT_ADDR`).
- **Robust sessions:** a session pool or re-login on token disconnect; a lost/again-required login must not wedge the service — but a token that is **unavailable fails closed** (see 2d), never falls back.

### 2d. Fail-closed (identical posture to incr-1)
Token unavailable / wrong PIN / key not found → `Encrypt` AND `Decrypt` **error** (no plaintext write, no weaker-cipher fallback). **Boot probe** (single-key mode) does a real on-token wrap+unwrap before serving → a misconfigured HSM **fails to boot**. `require-KMS` already makes `localCipher` unreachable — HSM is a valid provider under it.

## 3. THE CI invariant — the conformance suite must actually RUN against a real token
This was the deferral reason, and it is the load-bearing part of this gate (env-gated-green discipline — a green job that skipped proves nothing):
- Add a **SoftHSM2 service + cgo** CI job that builds with `-tags hsm` and runs the per-provider conformance suite + the 8 falsification tests against a **real PKCS#11 token** (SoftHSM2 initialised with a slot + a non-extractable test key).
- The HSM tests **fail closed when SoftHSM is absent** (a `RequireHSM` gate that **fatals, not skips** — exactly like `RequireDSN` for the RLS suite). A skipped HSM test is not a passing HSM test.
- This job is **blocking**. The boundary fence + the standard (non-hsm) build/vet also stay green (proving the tag isolation — the default build compiles cgo-free).

## 4. Falsification tests (the incr-1 set, now against SoftHSM + the HSM-specific)
1. **Round-trip per token:** `Wrap`→`Unwrap` returns the DEK; wrong-tenant AAD → fails.
2. **KEK non-extractable:** an attempt to read/export the key value is refused; a test asserts the key is created `CKA_EXTRACTABLE=false`/`CKA_SENSITIVE=true` and that no export path exists.
3. **Fail-closed token-down:** token/PIN unavailable → Encrypt+Decrypt error, no plaintext, no fallback; boot probe down → `New()` errors.
4. **Provider-confusion:** a `tagPKCS11` blob fed to a Vault/GCP cipher (or vice-versa) refuses loudly (reuses the proven 2c path).
5. **Per-tenant isolation:** tenant A's wrapped DEK cannot unwrap under tenant B's key label.
6. **Dual-read migration:** Vault→HSM (or GCP→HSM) via `transitionCipher` — old-provider ciphertext still decrypts (write-new/read-both), no orphan.
7. **require-KMS + tag isolation:** `require-KMS` refuses `localCipher`; and `provider="pkcs11"` in a **non-hsm build** returns the clear compile-out error (not a fallback, not a panic).
8. **DEK zeroize preserved** on the HSM path.

## 5. Out of scope (follow-ons / procurement)
The physical HSM procurement + FIPS/CC certification (a lab/procurement activity — SoftHSM proves the *code*, the cert is the *device*) · HSM HA/clustering topology (the HA/DR gate's DR-decrypt invariant covers "KEK reachable at DR") · cloud-HSM variants (AWS CloudHSM / Azure Managed HSM — same PKCS#11 surface, build on a signed need) · automated per-tenant key ceremony (first pass = documented onboarding step).

---
### Reviewer sign-off (I source-verify after the SoftHSM CI job is green)
- [ ] 1 — PKCS#11 provider behind `//go:build hsm`; default build is CGO-off/static (distroless unchanged); `provider="pkcs11"` in a non-hsm build errors clearly; boundary fence still covers the tagged file.
- [ ] 2a — keys `CKA_EXTRACTABLE=false`/`CKA_SENSITIVE=true`; wrap/unwrap on-token; no key-value read; provider purity holds (fence + test #2).
- [ ] 2b — per-tenant key by label/ID from `keyNameFor` (test #5).
- [ ] 2c — PIN from env/secret, never DB/logged; robust sessions; module/slot = infra config.
- [ ] 2d — fail-closed on token-down at boot AND runtime (test #3).
- [ ] 3 — SoftHSM2+cgo CI job runs the conformance + 8 tests against a REAL token, **RequireHSM fatals-not-skips**, blocking; standard build stays cgo-free.
- [ ] 4 — provider-confusion (test #4), dual-read no-orphan (test #6), DEK zeroize (test #8) all green against SoftHSM.
