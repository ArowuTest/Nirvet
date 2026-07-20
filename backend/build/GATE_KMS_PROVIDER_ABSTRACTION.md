# Pre-code Gate — KMS provider abstraction (HSM / Vault / multi-cloud) — reviewer-authored

Status: **CLEARED TO BUILD — reviewer-authored (Fable 5, Jul 20 2026), decisions LOCKED.** Loop: reviewer writes → builder implements → CI-green → reviewer source-verifies.
Origin: NIR-AUD-021 (sovereign/on-prem readiness) + the standing multi-agency-gov go-live blocker (`localCipher` single master key). **This one build clears the sovereign-cloud blocker AND unlocks on-prem/sovereign/air-gapped (Modes 3–5).** Ref: `outputs/NIRVET_ONPREM_SOVEREIGN_RECONCILIATION.md`.
Scope: **the crypto crown jewel.** Falsification bar: "what exposes a key, orphans a vault, or silently downgrades to weaker/absent crypto."

## 0. What is DONE (do NOT rebuild) — verified at source
The envelope layer is built and reviewer-verified (M1–M5). **This gate adds pluggable wrap/unwrap backends behind the EXISTING seam — it does not touch the cipher.**
- `keyWrapper interface { Wrap(ctx, keyName, plaintext, aad); Unwrap(ctx, keyName, ciphertext, aad) }` (`kms.go:52`) — the seam. `gcpKMS` implements it.
- `envelopeCipher{ wrapper keyWrapper, keyTemplate }` — owns DEK generation, AEAD, **per-tenant key resolution** (`keyNameFor` expands `{tenant}` → per-tenant/per-agency key), tenant_id-as-AAD, versioned ciphertext (`cipherKeyVersion`), **DEK zeroize** (`zero()`), and the single-key **boot probe** (`bootProbe`).
- `New()` 3-way mode selector (local / `transitionCipher` dual-read / pure envelope) + **`transitionCipher` = zero-downtime dual-read** (write-new / read-old+new) — the migration primitive.
**So a new provider = implement `keyWrapper` (Wrap/Unwrap) + register in `New()`. The envelope crypto is untouched.** Envelope encryption, per-tenant keys, rotation, and zeroize are DONE — this gate is the provider backend only.

## 1. The invariant every provider MUST preserve (the crux)
**The KMS/HSM-side key-encrypting key (KEK) NEVER leaves the KMS/HSM.** `Wrap` sends the DEK *to* the KMS and returns wrapped bytes; `Unwrap` sends wrapped bytes and returns the DEK. A provider that returns the raw KEK, exports key material, or performs the DEK↔plaintext AEAD itself **breaks the model and is rejected.** Providers do wrap/unwrap only; all plaintext crypto stays in `envelopeCipher`.

## 2. Design — LOCKED decisions

### 2a. Providers (build order)
Implement `keyWrapper` for each; selectable by config:
1. **Vault Transit** (first — software, sovereign-friendly, on-prem-standard). Per-tenant = a transit key per tenant (`keyNameFor` → transit key name).
2. **PKCS#11 HSM** (second — hardware, highest-assurance gov/defence). Per-tenant = a key label/handle per tenant.
3. **Azure Key Vault / AWS KMS** (cloud parity — DEFER unless a signed customer needs it; the gov target is on-prem/GCP).
GCP KMS stays as-is. Every provider MUST support the per-tenant `{tenant}` key model — a single-shared-key provider does not satisfy the sovereign per-agency isolation this whole build exists to deliver.

### 2b. `require-KMS` production mode (closes the "runs on the dev master key" gap)
Add an explicit config (e.g. `NIRVET_CRYPTO_REQUIRE_KMS=true`) that makes `localCipher` **unreachable** — `New()` **refuses to boot** without a real KMS provider. `localCipher` (single master key, "Dev/MVP only") must be impossible to select in a production/sovereign deployment, not merely discouraged. Seeded posture: dev unchanged; a documented go-live step sets require-KMS on.

### 2c. Provider-tagged ciphertext for safe migration
Extend the version/discriminator so a ciphertext records **which provider + key-generation wrapped it** (not just `cipherKeyVersion=1`). A provider switch or key rotation is then a **`transitionCipher` dual-read** (write-new-provider, read-old+new) — NEVER a big-bang swap that orphans an existing vault. Unwrapping a ciphertext tagged for provider A with provider B must **refuse loudly**, never return garbage.

### 2d. Provider credentials + fail-closed
- Provider secrets (Vault token/AppRole, HSM PIN, cloud creds) come from a **secure source** — env / mounted secret / instance identity (Workload Identity, Vault agent). **Never** the DB in plaintext; **never** logged.
- **Fail-closed everywhere:** provider unreachable/misconfigured → `Encrypt` errors (no plaintext write, no weaker-cipher fallback), `Decrypt` errors (no silent fallback), **boot probe fails → no boot** (extend `bootProbe` per provider, incl. per-tenant mode where the single-key probe is skipped today — define an onboarding-time probe).

## 3. Non-decorative GUARANTEE (the teeth)
- **Fence `scripts/check-kms-provider-boundary.sh`:** assert every `keyWrapper` implementation references ONLY wrap/unwrap primitives of its backend and **imports none of the envelope internals** (no DEK generation, no AEAD, no `zero()`), and that nothing outside `envelopeCipher` calls a provider's wrap/unwrap directly. Makes "a provider does its own crypto / leaks a key" structurally hard.
- **Boot-probe fence:** `New()` in a require-KMS build cannot return a `localCipher`; a test/fence asserts the require-KMS path fails closed without a provider.
- **Provider round-trip conformance suite** run against EACH provider (same test vectors), so a new provider can't ship without passing wrap→unwrap→identity + tenant-AAD binding.

## 4. Load-bearing falsification tests (each mutation-sensitive)
1. **Round-trip per provider:** `Wrap`→`Unwrap` returns the exact DEK; wrong-tenant AAD → unwrap fails.
2. **KEK-never-leaves:** the provider API exposes no key export; fence + a test that no code path returns raw KEK material.
3. **Fail-closed provider-down:** provider unreachable → `Encrypt` AND `Decrypt` error (assert NO plaintext written, NO fallback cipher used). Boot probe down → `New()` errors.
4. **Provider-confusion:** a ciphertext tagged provider-A + key-gen-N, fed to provider-B (or gen-M), **refuses** — never silently mis-unwraps. Mutation: drop the provider tag check → RED.
5. **Per-tenant isolation:** tenant A's wrapped DEK cannot be unwrapped under tenant B's key ref (per provider) — `{tenant}` separation holds for Vault/HSM as it does for GCP.
6. **Dual-read migration:** after switching provider via `transitionCipher`, old-provider ciphertext still decrypts (write-new/read-both) — **no data orphaned.** Mutation: single-read after switch → old vault unreadable → RED.
7. **require-KMS refuses localCipher:** with `require-KMS=true` and no provider, `New()` fails closed (does not fall to the dev master key).
8. **DEK zeroize preserved:** the `zero(dek)` defer still fires on every provider path.

## 5. Out of scope (follow-ons / ops, not code)
Specific HSM vendor selection + FIPS/CC cert · the key-ceremony + rotation runbook (ops doc) · GCP/Vault/HSM provisioning (env) · customer-managed-key onboarding UX · Azure KV / AWS KMS providers (build only on a signed customer need).

---
### Reviewer sign-off (I source-verify after CI-green)
- [ ] 1 — KEK-never-leaves invariant holds for each provider (wrap/unwrap only; no key export; no provider-side AEAD) — fence + test #2.
- [ ] 2a — per-tenant `{tenant}` key model works for Vault (and HSM) — test #5; no single-shared-key provider.
- [ ] 2b — require-KMS mode makes `localCipher` unreachable in prod — test #7.
- [ ] 2c — provider/key-gen-tagged ciphertext; cross-provider unwrap refuses (test #4); provider switch is dual-read, no orphaned data (test #6).
- [ ] 2d — provider creds from secure source (never DB/log); fail-closed on provider-down at boot AND runtime (test #3); DEK zeroize preserved (test #8).
- [ ] 3 — boundary fence + boot-probe fence + per-provider conformance suite, blocking in CI.
