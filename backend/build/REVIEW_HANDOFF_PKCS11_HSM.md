# Reviewer Handoff — PKCS#11 HSM Provider

## Scope

This increment implements the reviewer-gated PKCS#11 HSM provider for Nirvet without changing the established envelope-encryption design. The provider remains a `keyWrapper`; `envelopeCipher` continues to own DEK generation, AES-GCM data encryption, per-tenant AAD, provider/generation tagging, zeroization and dual-read migration.

## Build isolation

- Default production build remains CGO-free and excludes the PKCS#11 implementation.
- HSM implementation is compiled only with `-tags hsm` and `CGO_ENABLED=1`.
- A non-HSM build selecting `NIRVET_CRYPTO_PROVIDER=pkcs11` fails clearly with: `HSM support not compiled in — build with hsm tag`.
- The standard provider boundary fence includes the build-tagged PKCS#11 source and confirms that providers remain wrap/unwrap-only.

## Provider configuration

- `NIRVET_CRYPTO_PROVIDER=pkcs11`
- `NIRVET_KMS_KEY_NAME` must contain `{tenant}`.
- `NIRVET_HSM_MODULE_PATH` identifies the PKCS#11 module.
- Select the token with `NIRVET_HSM_SLOT_ID` or `NIRVET_HSM_TOKEN_LABEL`.
- `NIRVET_HSM_PIN` is read from the deployment secret environment only; it is not stored in the database or logged.
- `NIRVET_HSM_PROBE_KEY_LABEL` identifies a separate startup-probe KEK.

## Tenant isolation

For each tenant, `keyNameFor` resolves `{tenant}` to the tenant UUID. The HSM object lookup uses:

- `CKA_LABEL` = fully resolved tenant key name;
- `CKA_ID` = first 16 bytes of SHA-256 over that resolved name;
- class/key type = AES secret key.

PKCS#11 AES encryption has no AAD input, so HSM-layer isolation comes from distinct per-tenant KEK objects. The envelope payload remains independently bound to the tenant UUID through AES-GCM AAD. Wrong-tenant unwrap therefore fails at the KEK layer, and wrong-tenant envelope decryption remains refused at the data-encryption layer.

## Key ceremony requirements

Production keys are created during an authorised two-person ceremony. The provider does not create or import production KEKs.

Every tenant KEK and the separate probe KEK must be AES-256 token objects with:

- `CKA_TOKEN=true`
- `CKA_PRIVATE=true`
- `CKA_SENSITIVE=true`
- `CKA_EXTRACTABLE=false`
- `CKA_ENCRYPT=true`
- `CKA_DECRYPT=true`

The application validates these attributes before use and never requests `CKA_VALUE`. The ceremony record captures identifiers, custodians, approvals, generation and probe result, never the key value or PIN. The same requirements are incorporated into `build/runbooks/KEY_ROTATION.md`.

## Runtime behaviour

- Module and token selection fail closed.
- Login failure or wrong PIN fails at boot.
- Sessions are opened, authenticated and closed around token operations under a provider mutex.
- The startup probe performs a real token-side encrypt/decrypt round trip using the separate probe KEK.
- Missing, duplicated, incorrectly attributed or ambiguous KEKs are rejected.
- The local development cipher is unreachable when `CryptoRequireKMS=true` and PKCS#11 is selected.

## Cryptographic boundary

- Tenant DEKs are generated and zeroized by `envelopeCipher`.
- The KEK never leaves the token.
- No `CKA_VALUE` export is performed.
- No local AES implementation uses the KEK.
- Token operations wrap and unwrap only the DEK.
- Provider tag `tagPKCS11=3` prevents provider confusion.

## Blocking SoftHSM evidence

The dedicated CI job installs and initialises a real SoftHSM2 token, uses random masked PINs, builds with CGO and the `hsm` tag, and runs the following falsification checks as separately visible blocking steps:

1. Real-token round trip.
2. KEK non-extractability and blocked `CKA_VALUE` read.
3. Wrong PIN fails closed.
4. Provider confusion is refused.
5. Per-tenant KEK isolation.
6. Dual-read migration preserves old-provider ciphertext while new writes use HSM.
7. `require-KMS` selects HSM and does not fall back to local encryption.
8. Existing DEK-zeroization test remains green in the tagged build.

Latest verified run before final history cleanup: all HSM build, vet, boundary and eight falsification steps passed. Standard backend build, migrations, race tests, frontend build and `govulncheck` also passed. Final reviewer-ready status requires the clean-history branch to pass the same matrix, including Gitleaks and gosec.

## Files in scope

- `.github/workflows/ci.yml`
- `backend/go.mod`
- `backend/internal/platform/crypto/crypto.go`
- `backend/internal/platform/crypto/pkcs11_disabled.go`
- `backend/internal/platform/crypto/pkcs11_disabled_test.go`
- `backend/internal/platform/crypto/pkcs11_hsm.go`
- `backend/internal/platform/crypto/pkcs11_hsm_test.go`
- `backend/build/runbooks/KEY_ROTATION.md`

## Explicitly out of scope

- Physical HSM procurement and vendor certification.
- HSM clustering/topology design and automated failover.
- Cloud-HSM-specific adapters.
- Automated production key ceremony.
- Changes to the established envelope format or application-domain interfaces.

## Reviewer sign-off checklist

- [ ] Source-verify `//go:build hsm` / `//go:build !hsm` isolation.
- [ ] Confirm default CGO-free build and clear compile-fence error.
- [ ] Confirm `keyWrapper` boundary and no provider SDK leakage into domain code.
- [ ] Confirm per-tenant `{tenant}` resolution and deterministic label/ID mapping.
- [ ] Confirm `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false` enforcement.
- [ ] Confirm no `CKA_VALUE` read and no local KEK cryptography.
- [ ] Confirm real token startup probe and fail-closed PIN/session behaviour.
- [ ] Confirm all eight SoftHSM falsification checks are green.
- [ ] Confirm standard backend, race, security, secret and frontend checks are green.
- [ ] Confirm branch is aligned with current `main` and PR is mergeable.
