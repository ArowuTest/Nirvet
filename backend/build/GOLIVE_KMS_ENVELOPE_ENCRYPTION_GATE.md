# Pre-code Gate — A1 KMS: Cloud KMS envelope-encryption cipher (build + test now, provision later)

Status: **DRAFT — awaiting reviewer pass.** Loop: this note → reviewer pass → build → CI-green → reviewer source-verification.
Go-live blocker: **A1** (single master key). Task #162. Buildable + testable now with a fake; real GCP provisioning is later.

## 1. The blocker, verified at source

`internal/platform/crypto/crypto.go`: production `kmsCipher` is a **stub** (`NewKMS → errKMSNotImplemented`). The live path is `localCipher` — AES-256-GCM under **one** `NIRVET_SECRET_MASTER_KEY` for ALL tenants; `tenantID` is GCM **AAD only** (`aad := tenantID[:]`). AAD is a *binding* (A's ciphertext won't open in B's row) but **not key separation** — one leaked master key decrypts every agency's vault (Okta/Defender/Entra/connector creds, MFA secrets). For the multi-agency gov operator (≈250 agencies under one env-var key) that is the go-live blocker. Fix = real envelope encryption with **per-tenant KMS-wrapped data keys**.

Seam already present:
- `SecretCipher` interface: `Encrypt(tenantID, pt) ([]byte,err)` / `Decrypt(tenantID, ct) ([]byte,err)`.
- `cipherKeyVersion byte` prefix — explicitly the rotation/migration hook ("a future key can bump the version so decrypt selects the right key by the stored byte, without a data migration"). localCipher = version **1**.
- `New(kmsKeyName, masterKeyB64, log)` selects KMS when `kmsKeyName!=""` else local. Constructed ONCE at startup (`cmd/api/main.go:155`, `cmd/worker/main.go:98`) → a process singleton; `Encrypt` takes tenant per call.

## 2. Design — envelope encryption, per-op DEK, per-tenant KMS key

Per `Encrypt(tenantID, pt)`:
1. Generate a random 32-byte **DEK**; AES-256-GCM seal `pt` with the DEK, `aad = tenantID[:]` (keep the tenant binding).
2. **Wrap** the DEK by calling Cloud KMS `:encrypt` on the tenant's CryptoKey; store the wrapped DEK alongside.
3. Stored layout (**version byte 2**): `[2][uint16 len(wrappedDEK)][wrappedDEK][nonce][gcm-ciphertext]`.
`Decrypt`: read version → v2 path parses wrappedDEK, calls KMS `:decrypt` to unwrap the DEK, then AES-GCM opens with `aad=tenantID[:]`. The DEK lives in memory only for the op.

**Key separation (the actual fix):** the KMS key name comes from a **template** with a `{tenant}` placeholder, e.g. `projects/P/locations/L/keyRings/nirvet/cryptoKeys/tenant-{tenant}` → each agency's DEKs wrap under that agency's own CryptoKey. Compromising one agency's key never decrypts another's. A template with **no** placeholder = single-key mode (a strict improvement over localCipher — key in the HSM, per-op DEKs — but NOT multi-agency separation; document it as pilot-only). **Recommendation: ship the template/per-tenant form** since that is what the blocker requires and what the stub's TODO already specifies ("wrap the DEK with the tenant's KMS CryptoKey").

## 3. Transport — REST via SafeClient, NOT the gRPC SDK (matches the repo's pattern)

The project deliberately avoids heavy GCP SDKs (blobstore is S3-API `s3.go`; no `cloud.google.com/go` in go.mod; every connector is REST via `netsafe.SafeClient`). So the KMS wrapper is a **REST client** to `https://cloudkms.googleapis.com/v1/{keyName}:encrypt` / `:decrypt` through `netsafe.SafeClient`, bearer-auth with a GCP access token. This keeps the dependency surface flat, the govulncheck surface small, and makes it **httptest-fakeable** exactly like the Palo Alto / CrowdStrike / Okta clients.

**Testability seam:** a tiny interface
```
type keyWrapper interface {
    Wrap(ctx, keyName string, dek []byte) (wrapped []byte, err error)
    Unwrap(ctx, keyName string, wrapped []byte) (dek []byte, err error)
}
```
Two impls: `gcpKMS` (REST+SafeClient) and a test `fakeWrapper` (deterministic reversible transform + records the keyName it was called with, so tests assert per-tenant routing). The envelope logic (DEK gen, AES-GCM, layout, version byte) is provider-agnostic and fully unit-tested against `fakeWrapper` — no GCP needed. The real `gcpKMS` path is exercised only when configured with real creds (provision later).

**Auth (provision later):** GCP access token via a service-account (Workload Identity / SA-key file) — resolved lazily and cached to expiry, same shape as the CrowdStrike/Okta token flow. Absent creds ⇒ startup fails fast (see §5).

## 4. Zero-downtime cutover — version-discriminated dual-read (KEY DECISION for the reviewer)

Existing stored secrets are localCipher **v1**. `kmsCipher` writes **v2**. Cutover options:
- **(A, recommended) Transition cipher = dual-read.** `New()` (when KMS configured AND a legacy master key is still present) returns a composite: `Encrypt` → always v2 (KMS); `Decrypt` → dispatch on the version byte (v1 → retained localCipher, v2 → kms). Existing v1 blobs keep opening; new writes are v2. No data migration, no downtime. A later background re-encrypt sweep can upgrade v1→v2 and then the master key is retired. **Cost:** the old `NIRVET_SECRET_MASTER_KEY` must remain available through the transition (documented, time-boxed).
- **(B) Big-bang re-encrypt migration** at cutover (decrypt-all-local, re-encrypt-kms in one job). Simpler mental model, but a maintenance window + a migration that touches every secret row = riskier for gov.

Recommend **A** (the version byte was designed for exactly this). The gate needs the reviewer's call on A vs B because it changes the `New()` shape and the ops runbook.

## 5. Fail-fast + no-hardcoding

- `NewKMS` builds the REST client and does a **startup self-test** (wrap+unwrap a probe value against the configured key) → misconfig/missing-creds fails at boot, not on the first connector op. (Current stub already fails fast; keep that property.)
- Key-name template, KMS endpoint host, HTTP timeout, token source = config with seeded defaults (no literals) — per the no-hardcoding rule.
- SafeClient stays un-weakened (KMS is a public GCP host → permitted; no internal-egress carve-out).

## 6. Tests (fake wrapper; no GCP)

- **Round-trip**: Encrypt→Decrypt returns plaintext; ciphertext starts with version byte 2 and carries a wrapped DEK.
- **Tenant AAD binding**: a v2 ciphertext sealed for A fails to Decrypt under B (GCM tag) — the binding survives envelope.
- **Per-tenant key routing**: fakeWrapper records keyName; assert Encrypt(A) wrapped under `...tenant-A` and Encrypt(B) under `...tenant-B` (proves key separation, not just AAD).
- **Dual-read**: a v1 (localCipher) blob and a v2 (kms) blob BOTH decrypt through the transition cipher; Encrypt always emits v2.
- **KMS-down fails loud**: Unwrap error → Decrypt errors (never returns garbage / fake plaintext).
- **Tamper**: flip a wrapped-DEK or ciphertext byte → Decrypt fails.
- Mutation notes on the security-load-bearing ones (drop the AAD → tenant-binding test RED; hardcode one keyName → routing test RED).

## 7. Premises to verify at source during build (O-3 discipline — do NOT assume)

1. **Cipher singleton vs per-call key.** Confirmed `crypto.New` is constructed once at startup and `Encrypt`/`Decrypt` take tenant per call → the singleton holds the template + client and resolves the key name per-call. Re-read to confirm no caller assumes a fixed key.
2. **Every stored-secret producer/consumer goes through `SecretCipher`.** Grep all `Encrypt(`/`Decrypt(` / `Vault.Open` callers (connector creds, IAM service accounts/API keys, notify sender secrets, MFA secrets, AI provider keys) — the version-byte dual-read must cover ALL of them, and none may parse the ciphertext layout independently.
3. **`config` flow** for `KMSKeyName` / master key — where set, and whether both can be present at once (required for dual-read transition).
4. **GCS/#161 pattern** — confirm blobstore's provider seam (interface + S3 impl + fake) so the keyWrapper interface mirrors the established shape.

## 8. Out of scope / deferred
Real GCP project/keyring/CryptoKey provisioning + Workload Identity (needs the GCP env — the "provision later" half). The background v1→v2 re-encrypt sweep + master-key retirement (a follow-on once cutover is validated). Per-tenant key **rotation** schedule (KMS handles key versions; our version byte already leaves room).

---
### Reviewer sign-off — **PASSED with 5 conditions** (Fable 5, Jul 18 2026; all premises verified at source)

- [x] **Envelope design** (per-op DEK, tenant-AAD retained, v2 layout) — **SOUND.** Textbook envelope. Keeping `aad=tenantID[:]` on the inner DEK-seal is good defense-in-depth. → **M3** below.
- [x] **REST-via-SafeClient over gRPC SDK** — **AGREE (strong).** No `cloud.google.com/go` in go.mod, blobstore is S3-REST, connectors are REST via SafeClient. Pulling the KMS gRPC SDK would drag grpc + google.golang.org/api into the tree and enlarge the govulncheck surface. REST keeps it flat and httptest-fakeable — the whole point of build-now-provision-later.
- [x] **Per-tenant key template as default** — **CORRECT, ship it.** Single-key mode is a strict improvement (key in the HSM, per-op DEKs) but does NOT close the multi-agency blast radius — document it pilot-only. Precision: the security separation comes from the **per-tenant KEK (CryptoKey)**; per-op DEKs are hygiene, not separation (the gate gets this right in §2). → **M1, M5**.
- [x] **Cutover: dual-read transition cipher (A)** — **APPROVED over B.** The version byte was built for this; `localCipher.Decrypt` already does dual-layout; zero downtime, no migration. B (re-encrypt every secret row under a window) is riskier for gov. → **M2, M4**.
- [x] **Premise §7 #2** — **CONFIRMED BY REVIEWER AT SOURCE** (not relayed): all six secret consumers route through `crypto.SecretCipher` — connector `Vault`, `iam` MFA (`service.go:190/335/344/361/380`), `notify` senders, `sso` client secrets, `ticketing` creds, AI provider keys (`cipherSecretBox`, main.go:93). The `[version][nonce][ct]` layout is parsed **only inside crypto.go** — no consumer decodes it. So version-dispatch is a single chokepoint and the dual-read covers every consumer. Premise set is the right one.

**CONDITIONS OF THE PASS (all additive; fold before build → I source-verify after CI-green):**

- **M1 — per-tenant KMS failure FAILS CLOSED (crown-jewel of this slice).** A v2 op whose tenant KMS key is missing/unauthorized (NOT_FOUND / 403 from the wrapper) must HARD-ERROR and **must never fall back to localCipher / the master key**. A silent degrade to the shared key would re-open the exact blast-radius this slice closes. Add an explicit test: v2 Encrypt/Decrypt with a wrapper returning NOT_FOUND → error, and assert **no** localCipher path was taken. Mutation: wire a fallback → test RED. *(Zero-config-floor / fail-safe invariant: a per-tenant control that silently degrades to a shared key is worse than none — it reassures while not isolating.)*
- **M2 — Decrypt dispatches on the STORED version byte, not try-and-fallback.** The transition cipher selects v1→local / v2→kms by the stored byte; a v2 blob that fails KMS unwrap returns an **error**, never attempts a v1/local open. (Same discipline as O-3: act on the stored discriminator, not a runtime guess.) Test: v2 blob + KMS-down → error, and prove no v1 open was attempted.
- **M3 — bounds-check the v2 parser.** `[2][uint16 len][wrappedDEK][nonce][ct]` decode must validate `len` (and the nonce/ct remainders) against the buffer **before** slicing → a truncated/oversized/tampered blob returns a clean error, never an index panic. Extend the tamper test with a truncated length prefix and an oversized `len`.
- **M4 — `New()` must become THREE-WAY (verified at source — current logic blocks option A).** Today `New()` is mutually exclusive: `if kmsKeyName!="" → NewKMS(key)` (ignores the master key) `else → NewLocal`. Dual-read needs BOTH. Rework: `KMS+master → transition cipher (v2 write, dual-read)`; `KMS only → pure kmsCipher (post-transition, master retired)`; `neither → localCipher`. Thread `masterKeyB64` into the transition constructor. Without this the recommended cutover cannot even construct.
- **M5 — provisioning posture (document + code-shape).** Per-tenant means ~250 CryptoKeys. Decision: **pre-provision at tenant onboarding**, and the runtime service account holds **encrypt/decrypt only — NOT create/destroy** on the keyring (a compromised runtime must not be able to mint or delete agency keys). The adapter therefore treats NOT_FOUND as fail-closed (folds into M1), never auto-creates. (Auto-provision-at-onboarding wiring is "provision later"; the least-privilege boundary is a design commitment now.)

**SHOULD (not blocking):** bind `tenantID` as AAD on the KMS `:encrypt`/`:decrypt` (additionalAuthenticatedData) too — belt-and-suspenders atop the per-tenant KEK; cheap.

**Verdict: cleared to build.** Nothing rejected; the design is right. Build the adapter + fake-wrapper tests (§6 + M1/M2/M3 additions), CI-green, then I source-verify M1–M5 hold on the real code. The blocker is CLOSED only when a v2-under-per-tenant-key round-trips AND the fail-closed (M1) + dispatch (M2) properties are proven green — not merely when the adapter compiles.
