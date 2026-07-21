# Reviewer Evidence — Offline Content Lifecycle

Branch: `feature/offline-content-lifecycle`
Gate: `build/GATE_OFFLINE_CONTENT_LIFECYCLE.md`

## Signed fixture set

The committed `backend/internal/platform/contentlifecycle/testdata/` directory contains:

- `valid-pack.json`
- `tampered-pack.json`
- `unsigned-pack.json`
- `untrusted-publisher-pack.json`
- `expired-pack.json`
- `downgrade-pack.json`
- `cross-tenant-pack.json`
- `malformed-pack.json`
- `unsafe-rule-pack.json`
- `test-publisher.public.hex`
- `test-publisher.seed.hex`

The fixture suite independently verifies every signed fixture using the committed test publisher public key. Negative fixtures prove fail-closed refusal before activation.

## Quarantine → approve → activate → rollback drill

Automated drill: `TestLifecycle_QuarantineApproveActivateRollbackDrill`.

Expected append-only transition sequence:

1. importer-a imports global detection-rules v1 → quarantined
2. approver-b approves v1 → approved
3. activator-c activates v1 → active
4. importer-a imports v2 → quarantined
5. approver-b approves v2 → approved
6. activator-c activates v2 → active, v1 snapshotted
7. operator-d rolls back v2 → v1 restored active

Assertions:

- approver differs from importer;
- v2 is active before rollback;
- v1 is restored atomically after rollback;
- seven ordered audit events are present;
- the final audit event is `rollback`.

## Provenance sample

The active record retains the verified pack manifest and lifecycle actors. A tenant-scoped sample carries:

- publisher: `test-publisher`
- content type: `detection_rules`
- version: `1`
- scope: `tenant`
- tenant: `tenant-a`
- signed content hash from the manifest
- import, approval, activation actors and timestamps through the lifecycle record/audit events

`TestVerifyThenParse_DowngradeAndCrossTenantFixturesAreSignedAndTraceable` independently verifies the signed tenant fixture and its provenance fields.

## Structural fence mutation proof

The blocking workflow temporarily inserts a production Go file importing `os/exec`. `check-content-import-boundary.sh` must turn RED. The mutation is then removed and the same fence must return GREEN before tests continue.

The fence scans production files only, so negative-control strings in `*_test.go` do not create false positives.

## Air-gap evidence

`TestAcquire_AirGapNeverCallsFetcher` proves air-gap mode performs zero outbound acquisition. Connected acquisition accepts only exact operator-allowlisted HTTPS TAXII collection URLs and refuses credential-bearing, HTTP, or non-allowlisted endpoints before invoking the fetcher.

## Reviewer rerun

```bash
cd backend
bash scripts/check-content-import-boundary.sh
go test -v -count=1 ./internal/platform/contentlifecycle
```

The dedicated `Offline content lifecycle` workflow runs the formatting guard, production boundary fence, RED→GREEN mutation proof, and complete signed-package/lifecycle falsification suite.
