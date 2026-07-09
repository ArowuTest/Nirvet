# Nirvet — Implementation Spec
## (1) Admin-Configurable AI Providers  ·  (2) Host-Telemetry (osquery/Wazuh) Flow
**Author:** Lead reviewer (Fable 5) · **Date:** 2026-07-09 · **Status:** pre-build design spec — fold each part into `build/ARCHITECTURE_GATES.md` as its gate, build **after SOAR slice C**.

> Both items are **SRS-grounded, not gold-plating.** Item 1 is a **conformance gap** (the SRS already mandates it and it is unbuilt); item 2 is **in-scope infrastructure** (the adjacent-collector concept is already in the SRS). Sequencing: crown-jewel SOAR slice C first → item 1 (small, it's debt) → item 2 (pulled by sovereign/low-maturity GTM). Do the two *near-free design inclusions* now (item 1: decide the config shape; item 2: fold a host-event source into the §6.5 OCSF normalization design) so neither needs a retrofit.

---

# PART 1 — Admin-Configurable AI Providers

## 1.1 Why (SRS grounding — this is debt, not a new feature)
- **§1454** — global configuration shall include **AI providers**.
- **§1903** — "the system shall provide **model/provider configuration and data routing restrictions by tenant**."
- **§3842** — "final AI provider / **private model** strategy per country and regulated customer type."
- **doc 04 §31** — "configurable model routing for regulated tenants."

Today `ai/gateway.go` hardwires `https://api.anthropic.com` (`:29,:71`); only `apiKey` + `model` are configurable, and there is **no `ai_provider` config surface** in the schema. That is a gap against the SRS **and** the owner's no-hardcoding rule. The good news already in place: AI is **assistive-only** (`GuardNoAutoContain`, `Assistive`), and **optional with an offline evidence-only fallback** (`Available()==apiKey!=""` → `fallbackSummary`). So "AI off = zero LLM egress, SOC still works" is already true and is the baseline sovereign guarantee. This item adds the *"AI on, but on a provider/endpoint the tenant is allowed to use"* path.

## 1.2 Scope
**In:** a config-first AI-provider record (global default + per-tenant override); a provider abstraction with ≥3 kinds (`anthropic`, `openai_compatible`, `disabled`); per-tenant provider **pinning + restriction** (residency enforcement); a **platform-admin allowlist** of permitted model endpoints; vault-stored keys; audit of provider+model+output.
**Out (this slice):** streaming responses; multi-model routing per task-type; fine-tuning; a model gateway proxy service. Keep it: pick one resolved provider per (tenant, call), call it, audit it.

## 1.3 Data model (config-first, FORCE RLS, mirrors `soar_action_catalog`)

```
-- migration 00NN_ai_providers.sql
CREATE TABLE ai_provider (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NULL REFERENCES tenant(id),         -- NULL = global default
  provider_kind   text NOT NULL CHECK (provider_kind IN ('anthropic','openai_compatible','disabled')),
  display_name    text NOT NULL,
  base_url        text NULL,                                -- required when openai_compatible; must be allowlisted
  model           text NULL,                                -- required unless disabled
  api_key_ref     text NULL,                                -- vault secret ref; NULL for disabled or unauth local
  enabled         boolean NOT NULL DEFAULT true,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'))  -- one config row per tenant (+ one global)
);
ALTER TABLE ai_provider ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_provider FORCE ROW LEVEL SECURITY;
-- RLS: a tenant reads its own row + the global (tenant_id IS NULL) row; writes to a tenant row are tenant-scoped;
-- the global row + the allowlist + any restriction are PLATFORM-ADMIN only (see 1.6).

-- Platform-admin allowlist of permitted model endpoints (the SSRF guard — see 1.5)
CREATE TABLE ai_provider_allowed_endpoint (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  host         text NOT NULL,          -- exact host[:port] a base_url may resolve to (may be internal — that's allowed)
  scheme       text NOT NULL DEFAULT 'https' CHECK (scheme IN ('https','http')),  -- http only for an explicitly-approved on-prem endpoint
  note         text NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scheme, host)
);
-- global table, platform-admin managed, no tenant_id (it's a platform trust list).

-- Per-tenant AI data-routing RESTRICTION (§1903) — residency enforcement, platform-admin only.
CREATE TABLE tenant_ai_policy (
  tenant_id        uuid PRIMARY KEY REFERENCES tenant(id),
  allowed_kinds    text[] NOT NULL DEFAULT ARRAY['anthropic','openai_compatible','disabled'],
  -- a sovereign tenant is set to e.g. ARRAY['openai_compatible','disabled'] (no external SaaS LLM)
  updated_at       timestamptz NOT NULL DEFAULT now()
);
```

**Seed (preserve current behaviour):** one global `ai_provider` row `provider_kind='anthropic'`, `model` = the current default, `api_key_ref` = the existing key ref. Existing tenants resolve to this and nothing changes.

## 1.4 Provider abstraction (code)
Replace the concrete `Gateway` with an interface + a resolver. Keep the existing Anthropic HTTP call as one implementation.

```go
// ai/provider.go
type Provider interface {
    Complete(ctx context.Context, system, prompt string) (text string, model string, err error)
    Available() bool
    Model() string
}

// implementations:
//  anthropicProvider      — the current gateway.go logic (host stays api.anthropic.com; netsafe-exempt OK, fixed host)
//  openAICompatibleProvider — POST {base_url}/v1/chat/completions, OpenAI schema; base_url from an ALLOWLISTED endpoint
//  disabledProvider       — Available()=false, callers use fallbackSummary (existing behaviour)

// ai/resolver.go
// ResolveProvider(ctx, tenantID) Provider:
//   1. load tenant_ai_policy.allowed_kinds (default all)
//   2. load ai_provider for tenant (or global default)
//   3. if resolved kind ∉ allowed_kinds → FAIL CLOSED to disabledProvider (never silently use a forbidden provider)
//   4. build the provider; openai_compatible base_url MUST match an ai_provider_allowed_endpoint (else disabledProvider + audit)
```

`ai/service.go` calls `ResolveProvider(ctx, tenantID)` instead of holding a single `gw`. Everything downstream (assistive summaries, triage) is unchanged.

## 1.5 The critical security guard — ALLOWLIST, not block-internal
> This is the one place a careless "fix" breaks the feature. Do **not** wrap the LLM endpoint in `netsafe.SafeClient` / `IsInternalHost`-blocking the way OIDC/ticketing/SMS are guarded — a **self-hosted sovereign model is *legitimately* on an internal/private address** (an on-prem GPU box), which `IsInternalHost` would reject. Internal ≠ malicious here.

Correct guard for `openai_compatible`:
1. **Platform-admin allowlist** (`ai_provider_allowed_endpoint`): a config's `base_url` host[:port]+scheme MUST be an exact match of an allowlisted entry. Setting a non-allowlisted `base_url` is rejected at save time (`ErrBadRequest`) and the resolver fails closed to `disabled` if it ever sees one.
2. **Fixed path + no redirects:** the client only ever appends the fixed API path (`/v1/chat/completions`) to the allowlisted base; the HTTP client **disallows redirects** (a redirect off the allowlisted host is an error). No tenant-controlled path/host beyond the allowlisted base.
3. **The allowlist is the trust boundary** — because a platform admin curated it, an internal address on it is trusted on purpose. That's the whole point.
4. `anthropic` kind keeps its fixed `api.anthropic.com` host (unchanged; still netsafe-exempt because the host is a code constant, not tenant input).

Net: the only reachable outbound targets are (a) the hardcoded Anthropic host, or (b) a platform-admin-allowlisted endpoint. Tenant/admin input can never point the client at an arbitrary URL. SSRF closed **without** blocking the legitimate internal sovereign endpoint.

## 1.6 Config surface (admin-gated, audited, tighten-only)
- `GET/PUT /admin/ai/provider` (global default) + `GET/POST/DELETE /admin/ai/allowed-endpoints` + `PUT /admin/tenants/{id}/ai-policy` — **platform-admin only.**
- `GET/PUT /tenant/ai/provider` — **tenant admin**, but the chosen `provider_kind` must be within `tenant_ai_policy.allowed_kinds` and any `base_url` must be allowlisted; violations `403/400`.
- **Tighten-only:** a `tenant_ai_policy` restriction (e.g. "no external SaaS LLM") is set by platform-admin and **cannot be loosened by the tenant or a lower role** — same pattern as the SOAR/detection guardrails ("overrides may only tighten").
- **Audit:** extend `auditMeta` to record `provider_kind` + endpoint host + `model` + output (output already logged). Every provider *change* writes an audit row; every AI call's audit already carries the model — add the provider kind + endpoint.
- **Vault:** `api_key_ref` resolves through the existing credential vault (envelope-encrypted); a **credential-decrypt audit** fires when the key is unsealed for a call (same pattern as connector creds).

## 1.7 Verify plan
Unit: resolver order (tenant→global→disabled); restriction fail-closed (kind ∉ allowed → disabled, audited); allowlist enforcement (non-allowlisted base_url rejected at save + fails closed in resolver); openai_compatible request/response mapping; disabled→fallbackSummary.
Integration (real DB): a sovereign tenant pinned to `['openai_compatible','disabled']` **cannot** select `anthropic` (403); a config pointing at an **allowlisted internal** endpoint works (proves internal-is-allowed); a non-allowlisted base_url is refused; tenant isolation (no cross-tenant provider read under FORCE RLS); vault decrypt-audit present; assistive guardrails (`GuardNoAutoContain`) intact; **AI-off tenant still functions** (fallback).
Adversarial (fold into the gate's review): base_url pointing at metadata/169.254.169.254 is rejected unless a platform admin explicitly allowlisted it (documents that the trust is the admin's, deliberately); redirect off the allowlisted host is blocked; a lower role cannot loosen `tenant_ai_policy`.

## 1.8 Sequencing
After SOAR slice C. Gate it first (outbound-to-config surface). Small, high-value (closes SRS debt + unlocks sovereign AI). **Decide the config shape now** even if built later, so no other AI feature accretes on the hardcoded gateway.

---

# PART 2 — Host-Telemetry Flow (osquery / Wazuh → collector → normalize → detect)

## 2.1 Why + the SRS boundary
- **In scope:** §321–326 *"On-Prem / Air-Gapped Adjacent Collector — customer-side collectors normalize/filter/forward telemetry to platform; raw data residency configurable."* The ingest on-ramps (Syslog + Webhook/API collectors, backlog **E09 US-033…036**) already exist.
- **The §1.4 boundary:** "Replacing full enterprise EDR products… or **equivalent endpoint agents**" is out of scope. **We do NOT build an endpoint agent.** We ingest telemetry from a **customer-deployed OPEN agent** (osquery/Wazuh) into the in-scope collector. Forwarding telemetry into an on-ramp is ingestion, not EDR — **record this as a scope *clarification* in §1.4, not a breach.**
- **Why it matters:** it is the difference between serving and not serving the **no-EDR / low-maturity / sovereign** customer — plausibly Nirvet's *core* buyer. It also completes the sovereign path (self-hosted agent + onshore collector + onshore deployment = non-egressing).

## 2.2 Scope
**In:** new source kind(s) for host telemetry; a **host-event normalizer** mapping osquery/Wazuh output to the canonical/OCSF event; a seed **detection content pack** for host events; per-source auth + tenant scoping (reuse existing); connector **health** (US-032). Recommend/validate/**document** an open agent config — do **not** author an agent.
**Out:** building an agent; live bidirectional agent control (query push-down) — v1 is telemetry ingest only; agent auto-deployment.

## 2.3 Architecture (two supported topologies)
```
(A) Simple / direct:
    osquery (osqueryd, TLS logger)  ──►  POST /ingest  (kind=host_osquery, HMAC/API-key auth)  ──►  normalize ─► canonical ─► detection/correlation
(B) Managed / sovereign (adjacent collector, §321–326):
    Wazuh agents ──► Wazuh MANAGER (self-hosted onshore; normalize/filter/forward) ──► POST /ingest (kind=host_wazuh) ──► …
```
Both use the **existing push ingest** (`ingestion/handler.go Ingest`) + existing **source authentication** (US-036, HMAC/API key). Topology B's Wazuh manager *is* the in-scope adjacent collector and is what a sovereign deployment runs in-country.

## 2.4 Data model / code
- **Connector `Kind`s:** add `KindOsquery = "host_osquery"` and `KindWazuh = "host_wazuh"` (or a single `KindHostAgent`) to `connector/entity.go` + the allow-set in `connector/service.go`. Keep enum↔any-CHECK in sync.
- **Normalizers:** add `normalizeOsquery` / `normalizeWazuh` in `ingestion/normalize.go` (mirrors the existing 8: defender/m365/crowdstrike/okta/paloalto/guardduty/azuresentinel/gcpscc). Map host events → canonical fields, and → **OCSF classes** (this is the §6.5 design-inclusion):

  | Host event | OCSF class | Key fields to canonicalize |
  |---|---|---|
  | process exec | Process Activity (1007) | process name, cmdline, pid, parent, user, host |
  | file create/modify | File System Activity (1001) | path, action, hash, user, host |
  | logon/auth | Authentication (3002) | user, result, source, logon-type, host |
  | net connection | Network Activity (4001) | src/dst ip+port, direction, process, host |

  → **Design-inclusion NOW (near-free):** ensure the §6.5 canonical schema carries `host`, `process`, `file`, `user`, `network` field groups so these map cleanly rather than being bolted on later.
- **Detection content:** seed a **host detection pack** (rule-pack config already exists, §1454; detection-as-code slice built): suspicious process lineage, persistence (autoruns/services), credential access, lateral movement — **ATT&CK-mapped**, seeded from public **osquery packs / Wazuh rulesets / SigmaHQ**. Ships as a rule pack, tenant-overridable.

## 2.5 Security / sovereignty
- **Auth + isolation:** per-source credential (HMAC/API key, US-036); ingest is tenant-scoped (existing RLS on the event path). A source belongs to exactly one tenant.
- **Sovereignty:** agent + Wazuh manager + Nirvet all self-hostable onshore (osquery Apache-2.0; Wazuh GPLv2; Fleet MIT) — **nothing phones home to a vendor.** Non-egressing collection; pairs with onshore deployment (residency) and AI-off / self-hosted-model (Part 1) for an end-to-end in-country SOC.
- **Input hardening:** treat agent payloads as untrusted telemetry — size caps, schema validation, no field interpolated into SQL (parameterized), filename/path sanitation on file events (the same discipline applied to STIX/attachments).

## 2.6 Health (US-032)
Per-source **heartbeat / last-seen**; alert when a host source goes silent past a threshold (a silent endpoint is a detection gap — the SOC-worst-failure theme). Surface in connector health, not just a status field.

## 2.7 Verify plan
Ingest a representative osquery pack result + a Wazuh alert JSON → normalize → canonical (OCSF-mapped) → a seeded host detection **fires**; tenant isolation (source A's events never visible to tenant B); source auth rejects a bad HMAC; a malformed/oversized payload is rejected not panicked; health signal fires on source silence; §6.5 mapping round-trips the four event classes above.

## 2.8 Sequencing
**Now (near-free):** (a) write this as a gate in `ARCHITECTURE_GATES.md`; (b) fold the host-event source (2.4 field groups) into the §6.5 OCSF normalization design so it isn't retrofitted.
**After SOAR slice C:** build normalizer + kinds + seed detection pack + health, pulled by a concrete sovereign/low-maturity engagement or a decision to lead with that segment. It's SRS-aligned, so this is a *sequencing* call, not a scope one.

---

## Combined sequencing (both items)
1. **SOAR slice C** (crown-jewel, real containment) — nothing preempts it; gets its own adversarial round (reviewer task #34).
2. **AI provider config** (Part 1) — small, closes SRS §1454/§1903 debt; gate first; get the allowlist-not-block guard right.
3. **Host-telemetry flow** (Part 2) — gate now + §6.5 design-inclusion now; build after slice C, pulled by sovereign-first GTM.

Both parts get a reviewer pass on landing; Part 1's allowlist guard and Part 2's tenant-isolation + silent-source health are the specific things I'll verify against source.
