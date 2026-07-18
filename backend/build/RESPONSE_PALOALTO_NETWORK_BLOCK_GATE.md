# Pre-code Gate — Palo Alto (PAN-OS) network-block Actioner (`block_ip` ⇄ `unblock_ip`)

Status: **LANDED & VERIFIED — reviewer landing PASS (clean, no findings), CI-green (a2151c3).** Loop complete: gate → reviewer pass ✔ → build ✔ → CI-green ✔ → reviewer source-verification ✔.

**Reviewer landing verification (all at source):** catalog repoint touches only `connector_key`, `fleet_wide` from 0134 survives ✔ · reverse splits `ip|corrTag` and unregisters exactly ours (O-3 reuse) ✔ · foreign reverse-skip via `panForeign`→`changed=false` ✔ · `TestFleetWide_BlockIP_NeverAutoRuns` drives real `svc.Run`, mutation-proven, self-verifying instruction ✔ · §7.2 fail-loud: register/unregister errors propagate, RFC-1918 block surfaces as error not fake success ✔. The multi-run shared-quarantine-tag edge was checked and deliberately NOT flagged — it is inherent terminal-state (D2) reverse semantics, identical to the Defender/CrowdStrike/Okta vendors already passed; ref-counting would be a cross-cutting D2 change, not a Palo Alto fix.

**Build verification (builder):** gofmt/vet/`go build ./...` clean · 5 connector unit tests (register-with-corr, unregister-exact-by-prior-id, foreign-not-removed changed=false, fail-closed on missing creds) · from-zero 135 migrations apply on a fresh DB · `TestFleetWide_BlockIP_NeverAutoRuns` via the real `svc.Run` and **mutation-proven** (set block_ip fleet_wide=false → test goes RED; restore → green) · existing FleetWide tests unregressed. Files: `internal/connector/{entity.go,credresolver.go,paloalto.go,paloalto_actioner.go,paloalto_actioner_test.go}`, `internal/soar/fleetwide_block_ip_test.go`, `cmd/api/main.go`, `migrations/0135_paloalto_block_ip.sql`.
Owner pick: Palo Alto firewall = next response vendor (new network-containment axis).

## 1. Why this slice — and the armed-but-dead gap it closes (verified at source)

Current registered actioners (grep of `internal/connector/*_actioner.go`):
CrowdStrike `cs_isolate_host/cs_release_host/cs_block_hash/cs_allow_hash` · Defender `isolate_endpoint/release_endpoint` · Entra `disable_user/enable_user` · Okta `okta_suspend_user/okta_unsuspend_user/okta_revoke_sessions`.

**No actioner exists for `block_ip`, `block_domain`, or `network_block_all`.** Yet:
- `migrations/0036_soar_action_catalog.sql:60-64` seeds `block_ip`/`block_domain` with `connector_key='defender'` (Defender has no such actioner) and `network_block_all` (risk `business_critical`, empty connector_key).
- `migrations/0134_fleet_wide_authority.sql:20` marks `block_ip`, `block_domain`, `network_block_all` (and `block_hash`) `fleet_wide=true`.
- `migrations/0108_playbook_content_pack.sql` seeds playbook steps that reference them ("Block the source IP" → `defender:block_ip`, "Block destination domain" → `defender:block_domain`, "Network-wide block" → `""`:`network_block_all`).

So a seeded "Block the source IP" step resolves to an **unregistered** actioner and hits the truthful `simulate` fallback (`canAutoRun` → "no live actioner registered"). It is **armed-but-dead**: looks wired, does nothing real. This slice makes `block_ip` a real, governed, reversible firewall action. (Prevents the armed-but-dead footgun per the no-hardcoding/no-stubs rule.)

## 2. Scope — Slice A is `block_ip` ONLY

- **IN:** `block_ip` (add) ⇄ `unblock_ip` (remove). Connector `palo-alto` (Kind + ingestion mapper `normalizePaloAlto` already exist; add `KindPaloAlto = "palo-alto"` const in `entity.go`).
- **OUT (follow-on slices, called out so they are not silently "covered"):**
  - `block_domain` — PAN-OS has no ad-hoc domain block via the fast path (needs an External Dynamic List or custom URL category + a config **commit**). Different mechanism → its own slice. **Left untouched** (stays `defender`/dead) — this slice does not make it worse, and does not pretend to cover it.
  - `network_block_all` — `business_critical` break-glass. `Allowed()` already forbids `business_critical` auto-run under ANY mode, and it's `fleet_wide`; intentionally human-only. Not backed here.

## 3. Mechanism — User-ID registered-IP + Dynamic Address Group (DAG), NO config commit

Block an IP by **registering it (User-ID API) with a tag** (default `nirvet-quarantine`) that a customer-pre-created DAG matches; the customer's security policy denies that DAG. Rationale:
- **No `commit`.** Address-object + policy-rule + commit is slow, needs commit-locks, and is disruptive/racy on a shared firewall. Registered-IP tagging takes effect immediately without a commit. → chosen.
- **Reversible** cleanly: unregister the tag (User-ID `<unregister>`). No policy edits.
- **Idempotent-friendly:** re-registering an already-tagged IP is a no-op.
- PAN-OS XML API `type=user-id` `<uid-message><payload><register>/<unregister>` with `<entry ip=".." ><tag><member>nirvet-quarantine</member></tag></entry>`. API key via the connector's encrypted creds; base URL = the firewall mgmt host from connector config (admin-set, netsafe-guarded — see §5).

Customer prerequisite (documented, not silently assumed): a DAG matching tag `nirvet-quarantine` + a deny rule referencing it. Connector test-probe should check the DAG exists. (This is the honest analogue of "CrowdStrike prevent-IOC requires the tenant's prevention policy".)

## 4. Safety contract (mirrors the verified CS IOC pattern)

`block_ip`: `PreCheck: true, Reversible: true, Inverse: "unblock_ip"`, `Confirm: nil` (register is synchronous).
`unblock_ip`: `PreCheck: true, Reversible: true, Inverse: "block_ip"`, `Confirm: nil`. Registry-only inverse (not a catalog step), mirroring `cs_allow_hash`.

- **Own-vs-foreign attribution (MUST-3, the O-3 lesson applied):** on register, embed `ActionCorrelatorParam` (`run_id:step_index`) — PAN-OS `register` has no free-text comment, so attribution is carried by a **per-run persistent-tag** in addition to the quarantine tag, e.g. `nirvet-corr-<hash(run_id:step_index)>` (PAN-OS tags are the only per-entry metadata on a registered IP). PreCheck: if the IP is already registered with the quarantine tag,
  - carries OUR correlator tag → `changed=false` (goal-met, don't double-register) **but ours** — a reverse MAY unregister;
  - tagged by someone else / no correlator tag → `changed=false` and **foreign** — reverse must NEVER unregister.
  `priorState["action_id"]` = the bare registration handle (the IP, or `ip|corr-tag`) for the reconciler / reverse key.
- **Reverse keys on `prior_action_id`** forwarded by `ReverseRun` (the O-3 fix we just verified at `sliceb_reverse.go:72-82`): `unblock_ip` unregisters exactly the IP+correlator-tag we registered — never a foreign registration of the same IP. `changed==true` gate at `sliceb_reverse.go:52-53` stays the sole undo trigger.
- **FleetWide:** `block_ip` is already `fleet_wide=true` (mig 0134) → refuses auto-run under any authority mode; a human approves. Exercises the §A guard we just landed. Class-`high`.
- **netsafe.SafeClient** for all PAN-OS calls (CI net.Dial fence). Firewall mgmt host is typically an RFC-1918 address → SafeClient's prod internal-egress block must be reconciled: connector egress uses the same allow path as other connectors (verify how Defender/CS clients are permitted their hosts — see premises).

## 5. No-hardcoding (admin-config with seeded defaults)

Every tunable is a config record with a seeded default, not a literal:
- quarantine tag name (default `nirvet-quarantine`), correlator-tag prefix, PAN-OS API version, HTTP timeout, register-timeout.
Reuse the existing connector-config mechanism (whatever backs CS/Okta base-URL + creds); do not invent a new store.

## 6. Migration 0135 (minimal)

- `KindPaloAlto` const (`entity.go`).
- Repoint the **catalog** `block_ip` row `connector_key` `defender`→`palo-alto` (so the catalog names the real backing connector). This alone closes the armed-but-dead gap (§7.1 — catalog wins). `block_domain`/`network_block_all` untouched.
- **Audit-honesty (reviewer note):** the seeded playbook step JSON in mig 0108 still reads `"connector_key":"defender"` for the "Block the source IP" step. Execution now routes to `palo-alto` (catalog wins), so the step JSON is "says-one-thing-does-another" drift. Repoint that step's `connector_key` `defender`→`palo-alto` too in 0135 so the audit trail matches execution. (Correctness doesn't require it; honesty does.)
- Add `unblock_ip` as a catalog row? **No** — inverses are registry-only (cf. `cs_allow_hash` is not a catalog step). Confirm from-zero validity.

## 7. Premises to VERIFY at source during build (NOT assumed — this is the O-3 discipline)

1. **Step→actioner resolution key — RESOLVED at source (reviewer, in the gate pass).** `service.go:264-269`: `act := lookupAction(actMap, st.Action)` (`resolveAction` keys on `action_key` ALONE, `catalog.go:68`); `if act.ConnectorKey == "" { act.ConnectorKey = st.ConnectorKey }` — the step's `connector_key` is a FALLBACK, used only when the catalog row's is empty. The `block_ip` catalog row's `connector_key` is non-empty (`'defender'`), so the step JSON is never consulted for it. → **Repointing the catalog row is sufficient** to close armed-but-dead. Not an open question. (Build must still re-read to confirm no drift.)

2. **Reachability / egress path — RESOLVED (the reviewer's PASS condition). Palo Alto is the FIRST actioner whose target may be unreachable from Nirvet-cloud.** Every prior actioner targets a public cloud API (`api.crowdstrike.com`, `graph.microsoft.com`, `*.okta.com`); a PAN-OS *management* interface is typically on-prem/RFC-1918 behind the customer perimeter. So this is not just SafeClient reconciliation — it's "can a cloud SOCaaS reach the customer's firewall at all?"
   - **Slice A ASSUMES a Nirvet-cloud-reachable management endpoint:** Panorama with an exposed API, or a cloud NGFW (VM-Series in the customer VPC / an NGFW reachable over HTTPS). The connector's `base URL` is the admin-set management host; SafeClient-allowlist it exactly like the other connector hosts (mirror the Defender/CS egress allow-path — verify that path at build, do NOT weaken the SSRF guard). Build proceeds on this assumption.
   - **On-prem NGFW behind the perimeter is OUT of Slice A.** Nirvet-cloud cannot reach it directly; it needs a collector/relay INSIDE the customer network — the SAME on-prem-reach problem as the telemetry-sourcing gap (the open-agent forwarder, see the telemetry-sourcing note). That is a materially bigger slice (actioner + relay), deferred and explicitly NOT covered here. Slice A must FAIL LOUD (clear connector error), never silently, when the management endpoint is unreachable — no fake success.
3. **PAN-OS registered-IP metadata.** Confirm a registered IP can carry multiple tags and that unregister can target a single (ip, tag) — the attribution scheme depends on it. If PAN-OS can't do per-(ip,tag) unregister, fall back to: our reverse unregisters the IP from the quarantine tag ONLY if PreCheck attributed it as ours (correlator tag present), else no-op.
4. **`fleet_wide` clamp on repointed row.** After repointing `block_ip` to `palo-alto`, re-confirm `resolveActionCatalogMap` still yields `FleetWide=true` for it (the override-only-tightens path).

## 8. Tests (must drive real paths, assert real outcomes — no tautologies)

- `TestPaloAlto_BlockIP_RegistersWithCorrelatorTag` — mock PAN-OS captures the `<register>` payload; assert the IP + quarantine tag + correlator tag are sent.
- `TestPaloAlto_UnblockIP_UnregistersExactlyOurTag` — mock captures the `<unregister>` target; assert it unregisters the IP+correlator we registered (keyed on `prior_action_id`), not a bare IP match.
- `TestPaloAlto_ForeignRegistration_NotOursNotRemoved` — IP already quarantine-tagged WITHOUT our correlator → PreCheck `changed=false`+foreign → reverse skips (REVERSE-COMPOSITION BREAK on failure).
- `TestPaloAlto_BlockIP_NeverAutoRuns_FleetWide` — drive `svc.Run` granting per-action `contractual_auto`; assert `RunPendingApproval` (fleet-wide refuses auto-run), mirroring the CS block-hash fleet test.
- from-zero migration + schemacheck + gofmt/vet + net.Dial fence all green.

## 9. Out of scope / explicitly deferred
`block_domain` (EDL/URL-category + commit), `network_block_all` (break-glass), and the Palo Alto connector's Direction flip Read→Read+Write in the connector registry catalog card (cosmetic; confirm it doesn't gate execution).

---
### Reviewer sign-off — PASS (conditional on §7.2, now folded in)
- [x] Scope (block_ip only; domain/all deferred, not silently covered) — OK.
- [x] Mechanism (DAG registered-IP, no commit) — right call over address-object+commit (designs out the commit fail-open).
- [x] Attribution via per-run correlator TAG (PAN-OS has no comment field) — sound; PAN-OS analogue of the CS IOC `action_id`.
- [x] §7.1 step-vs-catalog resolution — reviewer SETTLED at source: catalog `connector_key` wins, step is fallback → repoint the catalog row is sufficient. (Not left as an open premise — "the kind that, unverified, becomes the next O-3.")
- [x] §7.2 reachability — ELEVATED to a build-blocker and RESOLVED: Slice A assumes a Nirvet-cloud-reachable mgmt endpoint (Panorama API / cloud NGFW); on-prem NGFW → relay-required, deferred (tied to the telemetry-sourcing forwarder gap); must fail loud when unreachable.

**At landing the reviewer will verify:** catalog row repointed (and `fleet_wide` survives it) · reverse keys on `prior_action_id` (unregisters exactly our ip+correlator, not a bare-IP match) · foreign-registration reverse-skip · fleet-wide-never-auto-runs test drives the real `svc.Run`.
