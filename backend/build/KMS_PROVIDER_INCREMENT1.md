# KMS provider abstraction — increment 1 (Vault Transit + shared machinery)

Implements `build/GATE_KMS_PROVIDER_ABSTRACTION.md`. The crypto crown jewel: pluggable wrap/unwrap backends behind
the existing `keyWrapper` seam. **The envelope cipher (DEK gen, AEAD, per-tenant key, zeroize, boot probe) is
UNTOUCHED** — this adds provider backends + the safe-migration + require-KMS machinery only.

## What landed (increment 1)
- **Vault Transit provider** (`vault.go`, `tagVault`): REST `transit/encrypt|decrypt`, per-tenant transit key via
  `{tenant}`, token from `NIRVET_VAULT_TOKEN` (env/secret, never DB, never logged), `associated_data` AAD binding.
  Client is a plain timeout client with an auditable `// netsafe-exempt` waiver — Vault addr is operator infra
  (`NIRVET_VAULT_ADDR`), not tenant input, and on-prem Vault is at a private address SafeClient would wrongly block.
- **Provider-tagged ciphertext** (2c): v2 layout is now `[ver=2][providerTag][keyGen][len][wrapped][nonce][sealed]`.
  `envelopeCipher.Decrypt` REFUSES a blob from a different provider/gen (test #4). No prod v2 blobs existed (GCP KMS
  was never provisioned), so extending the layout orphans nothing.
- **Generalized `transitionCipher`** (2c/#6): writes with the current provider, holds legacy-provider readers keyed
  by (tag,keyGen) → a provider switch is a dual-read, old vault never orphaned. A single-reader transition fails the
  old blob (proves the reader set is load-bearing).
- **`require-KMS` mode** (2b/#7): `NIRVET_CRYPTO_REQUIRE_KMS=true` makes `localCipher` UNREACHABLE — `NewFromConfig`
  fails closed without a provider (the master key is not an escape hatch). Wired through config + api/worker mains.
- **`gcp.go` split** out of `kms.go` so provider files are per-file purity-checkable. GCP path unchanged (tagged `gcp`).
- **Boundary fence** `scripts/check-kms-provider-boundary.sh` (blocking in CI): (A) provider files do wrap/unwrap
  ONLY — no `rand.Read`/AEAD/`zero()`; (B) `.Wrap(`/`.Unwrap(` is called ONLY from `envelopeCipher` (kms.go). Both
  teeth verified by mutation.
- **8 falsification tests + per-provider conformance suite** (`provider_test.go`) — all green locally; CI runs them
  under `-race` + from-zero migration + schemacheck.

## Deferred to increment 2 (flagged, not silently dropped)
- **PKCS#11 HSM provider.** It needs cgo + a native PKCS#11 library, and the §3 "conformance suite run against EACH
  provider" requires a **SoftHSM CI service** to test it. Shipping it untestable would violate that requirement.
  Increment 2 = add the PKCS#11 `keyWrapper` (`tagPKCS11` is already reserved) + a SoftHSM service in `ci.yml`.
- Azure KV / AWS KMS: per the gate, build only on a signed customer need.

## Config knobs (seeded dev-safe)
`NIRVET_CRYPTO_PROVIDER` ("" | gcp | vault) · `NIRVET_CRYPTO_REQUIRE_KMS` (false) · `NIRVET_VAULT_ADDR` ·
`NIRVET_VAULT_MOUNT` (transit) · `NIRVET_VAULT_TOKEN` (read by crypto, never stored/logged). Dev unchanged; the
documented go-live step sets provider=vault + require-KMS=true for sovereign deployments.
