# Pre-code Gate — Copilot completion, increment 3: RAG over case history (#180) — reviewer-authored

Status: **CLEARED TO BUILD — reviewer-authored (Fable 5, Jul 21 2026), decisions LOCKED.** Loop: reviewer writes → builder implements → CI-green → reviewer source-verifies.
Origin: capability audit §A — the copilot has no institutional memory; it can't recall a similar past incident or your knowledge base. This is the **third and final** mature-copilot piece (incr 1 = propose ✅, incr 2 = investigate ✅). It's the biggest lift and introduces a **new data surface** (embeddings + a vector store), so it gets the fullest falsification treatment.
Scope: **most security-sensitive AI increment.** Falsification bar: "what lets one tenant's copilot retrieve another tenant's data, leaks un-redacted content to the embedding model or the LLM, treats retrieved customer text as instructions, or resurrects deleted data."

## 0. The two non-negotiables
1. **The vector store is customer data — per-tenant, RLS'd, and NEVER retrieved across tenants.** A RAG that returns tenant B's past incident to tenant A's copilot is catastrophic. This is the crux.
2. **Retrieved content is UNTRUSTED DATA, not instructions.** Past-incident text/notes are customer telemetry — a retrieved chunk saying "ignore previous instructions" must be evidence, never a prompt. It rides the redacted evidence bag (the copilot-P0 untrusted-bag pattern), never the trusted task.

## 1. Current state, verified — the safe primitives to reuse
- `completeExternal` (verified) — the redaction chokepoint; the copilot-P0 refactor made raw customer data unrepresentable as a trusted param (untrusted-bag).
- `AssembleContext` + `dropInventedCitations` (verified) — cited, tenant-scoped, hallucination-stripped grounding.
- `KindOpenAICompatible` provider + allowlist + per-tenant residency policy + self-hosted-LLM enablement (verified) — the pattern the **embedding** provider must reuse.
- RLS + `WithTenant` (verified) — the tenant-isolation primitive the vector store must use.
- Retention-delete (mig 0116 + jurisdictional B3, verified) — the deletion path embeddings must honor.

## 2. Design — LOCKED

### 2a. Per-tenant vector store — RLS'd, the isolation crux
Embeddings live in a **tenant-scoped, FORCE-RLS'd table** (`tenant_id NOT NULL DEFAULT app_current_tenant()`, `tenant_isolation` + `owner_bypass`, same pattern as every customer table). Retrieval runs **`WithTenant(p.TenantID)`** — the similarity query is RLS-confined, so a tenant can only ever retrieve its own embeddings. A two-tenant test is the load-bearing proof: tenant A's retrieval never surfaces a tenant-B chunk. (pgvector or an equivalent in-Postgres index keeps it inside the RLS boundary — do NOT ship embeddings to an external vector DB that bypasses RLS.)

### 2b. Field-visibility on retrieval (retrieve as the analyst)
A retrieved chunk must respect the **acting analyst's field-visibility**, same as `RunHunt`/the assembler — a junior analyst's copilot must not retrieve a field a senior could see. Either index already-masked content per audience, or re-mask retrieved chunks for `p`'s role before they enter the bag. Retrieval is scoped to what the analyst could read directly.

### 2c. Embedding generation rides the redaction + provider controls
Generating an embedding **sends customer text to an embedding model** — an egress. It MUST go through the same controls as the copilot: an **allowlisted, per-tenant-policy-gated, air-gap-capable embedding endpoint** (reuse `KindOpenAICompatible` + the self-hosted-LLM enablement — a sovereign tenant runs a local embedding model), and the embedded text is **redacted first** (or the model is self-hosted so nothing leaves the perimeter). No raw customer data to a cloud embedding API for a strict/sovereign tenant.

### 2d. Retrieved chunks ride `completeExternal` as the untrusted bag
At query time the top-K retrieved chunks are added to the **redacted evidence bag** into `completeExternal` — never concatenated into the task/instruction. `check-ai-egress-redaction` stays green; the retrieved content is masked per the acting analyst on the way to the LLM. Citations to retrieved incidents are assembler/index-provided; `dropInventedCitations` strips invented ids.

### 2e. Retention-aware — deleted data leaves the index
When an incident/record is deleted or ages out (retention-delete, B3), **its embeddings are purged** — the RAG must never resurrect data the platform deleted. Wire embedding deletion into the retention/deletion path (or a reconcile sweep), and prove it: a deleted incident is not retrievable. Legal-hold and retention semantics carry to the index.

### 2f. Read-only + soar-free + bounded
RAG is retrieval (read); it adds no execute agency. `internal/ai` stays soar-exec-free (`check-ai-no-direct-execution` green); the RAG tool (if exposed to the incr-2 agent loop) is a **read-only** member of the closed tool registry (re-enters the tool-registry fence). Retrieval is **bounded** (top-K, K small) and embedding generation is bounded/rate-limited. Analyst-in-the-loop (per-conversation), not an autonomous indexer of everything without controls.

## 3. GUARANTEE (teeth)
- **Cross-tenant isolation:** the vector table is FORCE-RLS'd + `owner_bypass`; retrieval is `WithTenant`; a two-tenant DB-gated test proves no cross-tenant retrieval (mutation: drop the tenant scope → RED). Schemacheck covers the new RLS table.
- **`check-ai-egress-redaction`** stays green — retrieved chunks + embedded text both ride the redaction chokepoint; the embedding provider is allowlist-gated like the LLM.
- **`check-ai-no-direct-execution`** stays green — RAG is read-only; no soar/mutation symbol in `internal/ai`.
- **Untrusted-bag:** retrieved content enters only the evidence bag (a fence/test that no retrieved chunk reaches the trusted task/instruction param).

## 4. Falsification tests (each mutation-sensitive)
1. **Cross-tenant isolation (THE crux):** tenant A's copilot retrieval never returns a tenant-B chunk; `WithTenant` + RLS enforce it. Mutation: remove the tenant scope → tenant-B chunk retrieved → RED.
2. **Field-visibility:** a retrieved chunk is masked/filtered per the acting analyst's role (junior can't retrieve a senior-only field).
3. **Retrieved-redaction:** a customer identifier in a retrieved chunk egresses to the LLM masked (`completeExternal`).
4. **Untrusted-bag / injection-safe:** a retrieved chunk containing "ignore previous instructions" is treated as evidence, not a prompt — it enters the bag, never the task.
5. **Embedding egress control:** embedding generation goes to an allowlisted (+ per-tenant-policy) endpoint, redacted; a strict/sovereign tenant uses a self-hosted embedding model (no cloud egress).
6. **Retention-aware:** a deleted/aged-out incident's embeddings are purged and not retrievable.
7. **Read-only / soar-free:** the RAG path references no soar/mutation symbol; if exposed as an agent tool it's in the read-only registry (fences green).
8. **Citations:** retrieved-incident citations resolve to real indexed ids; invented ids dropped.
9. **Bounded:** retrieval is top-K bounded; embedding generation bounded/rate-limited.

## 5. Out of scope (follow-ons)
Cross-tenant "global threat knowledge" sharing (a deliberate, separately-gated feature — default is strict per-tenant) · continuous auto-reindex of the whole estate without controls · fine-tuning on customer data · multi-modal embeddings · a hosted external vector DB (must stay in-Postgres/RLS for the first slice).

---
### Reviewer sign-off (I source-verify after CI-green)
- [ ] 2a — vector store FORCE-RLS'd + `owner_bypass`; retrieval `WithTenant`; two-tenant no-cross-tenant proof (test #1); schemacheck covers it.
- [ ] 2b — retrieval respects the acting analyst's field-visibility (test #2).
- [ ] 2c — embedding generation redacted + allowlisted + self-hostable; no raw cloud egress for strict tenants (test #5).
- [ ] 2d — retrieved chunks ride `completeExternal` as the untrusted bag; injection-safe; citations grounded (tests #3, #4, #8).
- [ ] 2e — deleted/aged-out data purged from the index; not retrievable (test #6).
- [ ] 2f/3 — read-only, soar-free, bounded; fences (`check-ai-egress-redaction`, `check-ai-no-direct-execution`, tool-registry if agent-exposed) green (tests #7, #9).
