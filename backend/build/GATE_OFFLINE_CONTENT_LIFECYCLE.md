# Pre-code Gate — Offline content lifecycle + TIP feed automation (builder-2 item 4) — reviewer-authored

Status: **CLEARED TO BUILD — reviewer-authored (Fable 5, Jul 21 2026), decisions LOCKED.** Loop: reviewer writes → builder implements → CI-green → reviewer source-verifies. Answers the builder's gate request in full.
Origin: NIR-AUD-021 item 4 + the capability audit (thin detection content ~25 rules / ~15–18 techniques; TIP has no feed automation). This is the mechanism that lets an air-gapped sovereign SOC receive controlled rule/parser/TI updates — the biggest *product-content* gap.
Scope: **supply-chain security.** Imported content **runs** in the SOC. Falsification bar: "what activates tampered, unsigned, expired, downgraded, cross-tenant, or unsafe content — or lets imported content execute code or bypass an existing boundary."

## 0. The governing principle (everything else serves it)
**Imported content is DATA interpreted by the EXISTING safe engines — never executable code, and it can never do anything a manually-authored artifact can't.**
- A detection rule imports as data evaluated by the **existing CEL / allow-list→bound-params engine** (the same validated path I've verified for hand-authored rules). No new evaluation path, no `eval`, no raw SQL.
- A parser/normalizer is a **declarative field-mapping**, validated to contain no code / no unbounded-backtracking regex — never an executable transform.
- Content is detection / parsing / threat-intel / MITRE-mapping only. It **cannot** reference or trigger SOAR/actioners, grant a role, write authority/crypto/config, or reach any mutation surface. The response and authority boundaries are untouched.
This principle is enforced structurally (§3 fence), not just documented.

## 1. Content types + lifecycle states
**Types (all DATA):** detection rules (Sigma→the engine's CEL/predicate format), parsers/normalizers (declarative mappings), MITRE technique mappings, threat-intel (STIX 2.1 indicators/objects), trusted-cert bundles. **"Emergency patches" that are application *code* are OUT OF SCOPE** — that is a signed software release, not content; a content "emergency" is an expedited rule/parser/TI pack through this same pipeline.
**Lifecycle (fail-closed at every arrow):** `received → signature-verified → schema-validated → semantic-validated → quarantined → approved (four-eyes) → staged → active → (superseded | rolled-back | expired)`. Content is **never active before approval**; a failure at any gate stops the pack in quarantine-rejected.

## 2. Signed packages + trusted-publisher verification (verify-then-parse)
- A content package is a **signed artifact**: a detached signature over the WHOLE package (content + manifest: type, monotonic version, publisher id, issued/expiry, content hash). **Verify the signature BEFORE parsing any content** — never parse untrusted bytes; a tampered pack fails signature and is rejected before its content is touched.
- **Trusted publisher:** signature verified against an operator-managed **allowlist of publisher public keys/certs** (padmin). Unknown/untrusted publisher → refuse. Key rotation is an audited padmin action (ties the HSM/KMS key-ceremony discipline).
- The manifest's content hash is re-verified against the bytes (defense-in-depth over the signature).

## 3. Schema + semantic validation (reuse the existing safe validators)
- **Schema:** the pack matches the expected schema per type (a rule has valid fields; a STIX object is valid STIX; a parser mapping is well-formed). Malformed → refuse.
- **Semantic (the crux):** each artifact passes the **SAME validator the manual authoring path uses** — a detection rule compiles through the existing CEL/allow-list engine (no raw SQL/code, no forbidden field/action ref); a parser is validated declarative (no code, bounded regex); STIX indicators validate + normalize to the verified threatintel store. **Imported content therefore can do NOTHING a hand-authored artifact can't** — same engine, same bounds.
- **Structural fence `check-content-import-boundary.sh`:** assert the content-import/activation path references **no** `eval`/exec/`os/exec`/reflection-invoke, **no** soar/connector/actioner symbol, and **no** authority/crypto/grant/config-write. Content is interpreted, never executed; it never reaches the response or authority surfaces. Mutation-proven (add an `exec`/soar ref in the content path → RED).

## 4. Replay / downgrade / expiry / rollback protection
- **Replay:** monotonic `version` + issued-timestamp per publisher+type; re-importing a superseded or equal version is refused (or an idempotent no-op) — a captured old pack can't be replayed to activation.
- **Downgrade:** cannot activate a version **older** than the current active (prevents reverting to a removed/vulnerable rule); a genuine downgrade needs an explicit padmin + four-eyes override, audited.
- **Expiry:** an expired manifest → refuse activation (fail-closed); STIX indicators honor `valid_until`.
- **Rollback:** activation snapshots the prior active set; a bad activation rolls back atomically to the known-good prior. Rollback is always safe (revert to a previously-approved state).

## 5. TIP feed acquisition / normalization / dedup
- **Acquisition, two modes (§6):** connected = TAXII 2.1 poll from an **allowlisted** collection (operator config, SSRF-safe like every outbound); air-gap = **manual signed-bundle import only** (no outbound). Both feed the SAME signature+validation pipeline.
- **Normalization:** to the existing verified STIX store model (`threatintel`), not a parallel store.
- **Dedup:** idempotent on `(id, modified)` — the existing verified `UpsertStix` pattern; no double-count, no drift. Sighting/confidence semantics reuse the verified enrichment.

## 6. Air-gapped vs connected modes
- **Air-gap mode:** manual import only — an operator carries in a signed pack; **zero outbound feed acquisition** (no phone-home; ties the air-gap NetworkPolicy — no feed egress rule). This is the sovereign default.
- **Connected mode:** controlled TAXII poll from an allowlisted source, still fully signed+validated+quarantined+approved.
- The two modes differ ONLY in acquisition; validation/quarantine/approval/activation are identical.

## 7. Tenant scoping + provenance
- Content is **GLOBAL** (operator-published, applies to all tenants — like the seeded packs; padmin-only) or **tenant-custom** (a tenant's own, RLS-scoped). A tenant can never publish global content or affect another tenant; global is padmin.
- **Provenance:** every active artifact carries its source — publisher, package version, signature ref, content hash, import + approval actors + timestamps. Any active rule/indicator traces to its signed origin (an auditor requirement).

## 8. Quarantine + approval workflow
- Imported content lands in **quarantine** — validated but NOT affecting the SOC.
- **Four-eyes approval:** a senior (approver ≠ importer, creator≠approver, reuse the report-approval/SOAR four-eyes machinery) reviews the validated pack + its provenance and approves before activation. Destructive-adjacent content (e.g. a pack that disables/replaces existing rules) gets the stricter bar.
- Approved → **staged activation** (reversible, §4 rollback).

## 9. Fail-closed (atomic)
Invalid signature / unsigned / untrusted publisher / expired / malformed / semantic-invalid / downgrade-without-override → **refuse, never activate.** A pack is **atomic**: any invalid artifact rejects the WHOLE pack (no partial activation). A validation/verify error is a refusal, never a best-effort partial import.

## 10. Audit + reviewer-verifiable fixtures
- **Audit** every lifecycle transition (import, verify, validate, quarantine, approve, activate, rollback, reject) — actor, pack, type, version, publisher, result — append-only.
- **Reviewer-verifiable fixtures:** a **test-publisher keypair** + signed test packs committed as fixtures: a valid pack, a signature-tampered pack, an unsigned pack, an untrusted-publisher pack, an expired pack, a downgrade pack, a cross-tenant pack, a malformed pack, and an **unsafe-rule pack** (a rule that tries to reference a SOAR action / raw SQL / forbidden field). These let me independently exercise the pipeline.

## 11. Falsification tests (each mutation-sensitive; the builder's list, formalized)
1. **Signature tampering:** content or manifest altered after signing → verification FAILS → rejected before parse.
2. **Unsigned / untrusted publisher:** unsigned, or signed by a non-allowlisted key → refused.
3. **Malformed content:** schema-invalid rule/STIX/parser → refused at schema validation.
4. **Replay:** re-import a superseded/equal version → refused (or idempotent no-op).
5. **Downgrade:** activate an older version than current active → refused without explicit override.
6. **Expiry:** expired manifest / STIX `valid_until` passed → refused activation.
7. **Cross-tenant leakage:** tenant A's imported content never affects/leaks to tenant B; global is padmin-only (two-tenant test).
8. **Unsafe rule activation:** a rule referencing a SOAR action / raw SQL / forbidden field is **rejected at semantic validation** (the existing safe validators) — imported content can't do what a manual rule can't.
9. **No code execution (THE crux):** a pack cannot inject executable code; a "parser" cannot `eval`; a rule cannot escape the CEL/allow-list sandbox → fence + test.
10. **Fail-closed atomic:** a pack with one invalid artifact → the WHOLE pack refused (no partial activation).

## 12. Minimum CI gates + reviewer evidence (before "ready")
**CI gates (all blocking):**
- Signature verify tests (valid + tampered + unsigned + untrusted-publisher) green.
- Schema + semantic validators tested; unsafe-rule pack rejected via the existing engine's validator.
- The 10 falsification tests green against the committed signed fixtures.
- **`check-content-import-boundary.sh`** fence green + mutation-proven (RED on an `exec`/soar/authority-write ref in the content path).
- New content/vector tables: schemacheck (FORCE-RLS + owner_bypass for tenant-scoped tables) + from-zero migration green.
- Fail-closed atomicity test (partial pack → whole-pack refusal).
- Air-gap mode: a test proving no outbound acquisition when air-gap is set.

**Reviewer evidence (I verify at source + independently CI-confirm):**
- The signed test fixtures + the test-publisher keypair (so I re-run the pipeline).
- A captured **quarantine → approve → activate → rollback** drill (evidence, like the B8/DR drills — the lifecycle actually exercised end-to-end).
- The provenance record of a sample active artifact (traceable to its signed source).
- The fence mutation-proofs (RED→GREEN) for the content-import boundary.

---
### Reviewer sign-off (I source-verify after CI-green)
- [ ] 0/3 — content is data via the existing engines; `check-content-import-boundary.sh` proves no eval/soar/authority-write in the content path (test #9).
- [ ] 2 — verify-then-parse; signature over the whole pack; trusted-publisher allowlist; hash re-check (tests #1, #2).
- [ ] 3 — schema + semantic validation reuse the manual-authoring validators; unsafe rule rejected (tests #3, #8).
- [ ] 4 — replay/downgrade/expiry refused; rollback atomic to prior-approved (tests #4, #5, #6).
- [ ] 5/6 — TAXII (allowlisted) + manual import; air-gap = no outbound; dedup idempotent (STIX id+modified).
- [ ] 7/8 — tenant-scoped (global=padmin), provenance recorded; quarantine + four-eyes approval (test #7).
- [ ] 9/10 — fail-closed atomic (test #10); full audit; signed fixtures + the drill evidence; CI gates §12 all green.
