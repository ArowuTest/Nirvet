# Nirvet — Gov Go-Live Hardening Track (Track #2)

**Date:** Jul 16 2026. **Owner decision:** three-track parallel GTM — (1) gov *sell* now (free, no code),
(2) **gov go-live hardening** (THIS doc — real builder work, sequenced to *lead* private features), (3) private
feature-build (`NIRVET_RESPONSE_COVERAGE_BUILDOUT.md` — G1 Okta→CrowdStrike, then G7/G4/G2).

**Why this track leads:** a signed gov customer who cannot actually go live is the worst outcome, and a *live
reference customer* — even a government one — de-risks the private sales motion more than any actioner. The one
builder is shared, so track #3 (private) interleaves *behind* the hardening milestones below, not ahead of them.

**Method:** every "state" line below was read at source on `main` (not relayed). Sizes are estimates vs. existing
patterns, not measured.

---

## The four hardening items, sized against VERIFIED current state

| # | Item | Verified state at source | Go-live severity | Effort | Blocker for gov? |
|---|------|--------------------------|------------------|--------|------------------|
| H1 | **KMS envelope-encryption for the credential vault (ADR-0004)** | **STUB.** `internal/platform/crypto/crypto.go`: `kmsCipher` returns `errKMSNotImplemented`; prod path is `localCipher` wrapped by `NIRVET_SECRET_MASTER_KEY` (env). TODO(ADR-0004) present. GCS blob adapter (#161) already built, so cloud-portability groundwork exists. | **HIGH** for a *sovereign* claim (tenant connector secrets must be KMS-wrapped, not env-key-wrapped). Not a *pilot* blocker (local cipher is real AES, persistent key works). | L | **Yes for the sovereignty story**, no for a pilot. |
| H2 | **F3 ROE onboarding surface / arm-gate 409 window** | **DONE** (#224). `soar/protected_ack.go` + `sliceb_gate.go` present; ROE step closes the arm-gate window so destructive SOAR can't be armed before protected-targets are designated. | — (verify-only) | XS | No — already closed. Re-verify in the go-live pass. |
| H3 | **Value-loop soak / scale at volume** | **PARTIAL.** `build/SOAK_GATE_REPORT.md` exists = infra-layer PASS; the *value loop* (ingest→detect→correlate→SOAR) has **never run at volume**. | **HIGH** — a gov estate will push real event volume day one; an unproven value loop is a live-incident risk. | M | **Yes** — must run a real soak before a gov go-live sign-off. |
| H4 | **Render → GCP sovereign migration** | **FUTURE.** App is cloud-portable (BlobStore/ADR-0005, GCS adapter #161, NATS/ClickHouse adapters); no GCP deploy artifact yet. Free Render PG expires 2026-08-12. | **HIGH** for a Ghana *sovereign* deployment (data must live in-jurisdiction). | L–XL | **Yes** for sovereign go-live; the pilot can run on Render. |

**One-line:** H2 is done; **H1 (KMS), H3 (soak), H4 (GCP) are the three real gov go-live long-poles.** H1 pairs
naturally with H4 (both are GCP-native), so sequence H3 (soak — proves the product) → H1+H4 (GCP+KMS — proves the
sovereign deployment) unless the gov contract front-loads the residency requirement.

---

## Recommended track-2 sequence

1. **H3 — value-loop soak at volume.** Highest information-per-effort: it either proves the core product holds at
   gov scale or surfaces the scaling bug now instead of in front of a government customer. Extend
   `SOAK_GATE_REPORT.md` from infra-PASS to value-loop-PASS. Gate: define the target event rate + duration with
   the owner, then run it.
2. **H1 — KMS envelope-encryption** (closes task #162). Implement `kmsCipher` via `cloud.google.com/go/kms`:
   generate DEK → wrap with the tenant KMS CryptoKey → store `{wrappedDEK, ciphertext}` → decrypt unwraps via KMS.
   Keep `localCipher` as the non-sovereign/dev fallback (config-selected on `NIRVET_KMS_KEY_NAME`). Pre-code gate
   required (crypto surface). Ships dormant until a KMS key name is configured — same dormant-until-configured
   discipline as the actioners.
3. **H4 — GCP deployment** (co-sequenced with H1, since KMS is GCP-native). Stand up the sovereign GCP instance;
   the portability adapters already exist, so this is provisioning + wiring, not a rewrite.
4. **H2 — verify-only** in the final go-live pass (already built).

**Protection rule (owner directive):** track #3 (private features, starting the Okta actioner) may proceed *in
parallel* but must not starve this track — H3 soak in particular gates any gov go-live sign-off and should not slip
behind private-feature work.

Ties [[reference_nirvet_golive_roadmap]], [[project_nirvet_ghana_operator]], [[project_nirvet_capability_gaps]],
`NIRVET_RESPONSE_COVERAGE_BUILDOUT.md` (track #3).
