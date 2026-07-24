# Pre-code Gate — Supply-chain signing + SBOM + provenance — reviewer-relayed

Status: **CLEARED TO BUILD — reviewer-authored gate relayed by the project owner on 23 Jul 2026. Decisions LOCKED.**

## Mandate
Every deployable artifact — container images, binaries, the Helm chart, and the air-gap bundle — is signed by immutable digest, carries signed provenance back to the reviewed commit, ships with an accurate generated signed SBOM, and is verified before run, fail-closed.

The sovereign requirement is load-bearing: the complete trust chain MUST verify fully offline at an air-gapped installation using operator-controlled trust anchors. Verification MUST NOT depend on Rekor, Fulcio, a public registry, transparency-log lookup, OIDC, or any network phone-home.

## Existing substrate
- Build on deployment packaging commit `8ec5a05552129fac187463891041f9a09138a36c`; do not rebuild the packaging architecture.
- Signing-key custody uses the existing KMS/HSM operating model. Private signing keys are not shipped in artifacts or bundles. Air-gapped operators receive only public trust anchors and signed release material.

## Locked requirements
1. Every deployable artifact is identified and signed by SHA-256 digest; filenames/tags are never trust identities.
2. Every artifact has a generated SBOM tied to that exact digest. The SBOM is itself signed and dependency completeness is verified against authoritative lockfiles/build metadata.
3. Every artifact has signed provenance identifying the reviewed source commit, builder identity, build recipe, invocation parameters, artifact kind, version/release sequence, and subject digest.
4. Verification is mandatory before image load, binary execution, Helm install/upgrade, migration execution, or air-gap bundle import. Failure blocks the operation.
5. Operator trust anchors are local, explicit, versioned and replaceable. Unknown, missing, expired, revoked, or wrong keys fail closed.
6. Verification must be fully offline. No online identity, registry, transparency-log, or certificate-chain service may be required.
7. The air-gap bundle manifest is complete and closed: unlisted files, missing listed files, duplicate paths, digest mismatches, unsigned metadata, or nested artifact failures reject the bundle.
8. Downgrade protection is mandatory. A release below the operator-approved minimum release sequence or below the locally recorded installed sequence is rejected.
9. Signature/provenance/SBOM verification must happen before parse, extraction, load, install, migration, or execution.
10. Signing integrates with KMS/HSM custody through a signer boundary; the verification path is public-key only and has no secret dependency.

## Non-decorative guarantee
A structural fence `scripts/check-artifact-verification-gate.sh` runs in blocking CI and fails if any deploy/install path bypasses verification, if any deployable is absent from the signed manifest, or if the verification implementation is removed.

CI contains mutation proofs:
- strip a signature or signed-envelope reference → RED;
- add an unlisted dependency/artifact → RED;
- remove install/load/execute verification → RED;
- restore source → GREEN.

A network-dropped offline drill builds a representative release, signs every subject, removes network access, verifies using only local operator trust anchors, and proves install/load cannot proceed after any failed verification.

## Falsification tests
1. Unsigned artifact → RED.
2. Tampered artifact/digest mismatch → RED.
3. Wrong/untrusted/revoked key → RED.
4. Forged provenance or source-commit mismatch → RED.
5. Lying/incomplete SBOM or unlisted dependency → RED.
6. Downgrade/replay below minimum or installed release sequence → RED.
7. Offline verification with network unavailable → GREEN without phone-home; any network dependency → RED.
8. Remove or bypass verify-before-run/install/load → structural gate RED.

## Closure evidence
- source-verifiable signer/verifier and trust-anchor format;
- signed artifact/SBOM/provenance fixtures;
- complete release manifest covering images, binaries, Helm chart and air-gap bundle;
- all eight falsification tests;
- mutation-proven structural fence;
- network-dropped offline drill;
- blocking CI evidence;
- reviewer source verification before merge.
