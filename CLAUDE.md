# CLAUDE.md — operating guide for agents working in this project

## What this project is

The planning & knowledge base for **Nirvet** (*Network Intelligence, Risk Visibility & Event Triage*) — a
**SOC-as-a-Service platform**: a modular Cyber Security Operations Platform delivered as SOCaaS / MDR / Managed
XDR / Sovereign SOC / Enterprise Private SOC / MSSP white-label. **The application now exists and runs:**
`backend/` (Go API + ingest worker + migrations), `frontend/` (Next.js console), `deploy/` (docker-compose,
Dockerfiles, render.yaml). `docs/` remains the requirements source of truth. **"Nirvet" is the product name; use
it in code, docs, and UI.** See [RUNNING.md](RUNNING.md), [build/adr/](build/adr/), [build/ARCHITECTURE_GATES.md](build/ARCHITECTURE_GATES.md).

**Absolute path of this project:** `…\local_5a50be95-4a7b-45ca-9925-11a0fdb20500\nirvet`
(sibling of the session `outputs` directory). If you reached this via the project memory file
`project_nirvet.md`, that memory records the current path.

## Read order for a cold start

1. [knowledge/platform-overview.md](knowledge/platform-overview.md) — one-page orientation.
2. [INDEX.md](INDEX.md) — full artifact catalogue.
3. [docs/markdown/00_SRS.md](docs/markdown/00_SRS.md) — canonical full spec (20 sections). Use its
   **Section index** to jump; it is large.
4. Specific suite docs 01–06 as needed.

## Conventions — read before editing anything

- **`docs/source/` is immutable.** Those `.docx`/`.pdf`/`.xlsx` are the originals. **Never edit or delete them.**
- **`docs/markdown/` is derived** from the sources for readability/search. On any conflict, **the source file
  wins.** If you update a markdown file, note what changed and why; do not let it silently drift from the source.
- **`knowledge/` is synthesized** cross-document reference. It may lag the sources — treat it as a map, not the
  territory.
- The **SRS is the deepest requirements source**; docs 01–05 are the concise suite; doc 06 is the backlog.
- When you add real project material later (code, ADRs, infra), keep this structure and extend `INDEX.md`.

## Non-negotiable product invariants (carry into any build work)

These come straight from the spec and must hold for **every** feature you design or implement:

1. **Native-first, integration-first, not integration-dependent** — the platform works on basic
   syslog/API/webhook feeds and degrades gracefully without any specific vendor tool.
2. **Tenant isolation everywhere** — every query, object, file, vector embedding, and action is tenant-scoped;
   isolation is tested in CI/CD.
3. **Authority-to-act gating** — no destructive/business-impacting response without tenant policy + approval
   (observe → approval → pre-authorised → emergency).
4. **AI is assistive, never autonomous** — AI summarises/suggests/drafts; only the SOAR engine executes actions,
   under approval. AI outputs must separate observed evidence from inference and be logged.
5. **Audit everything** — immutable append-only audit for login/admin/analyst/AI/SOAR actions.
6. **Definition of Done** — a feature is portal/API-exposed, tenant-scoped, audited, tested, and documented.
7. **Nothing hardcoded; no TODOs** (owner directive, Jul 2026) — every business policy (SLA targets, correlation
   windows, risk-score weights, rate limits, escalation/routing, retention, authority-to-act, feature toggles) is an
   **admin-configurable DB record** read at runtime, shipped with a **seeded default row** (default lives in data,
   overridable via an admin API) — never a code constant. No `TODO`/`FIXME` markers: if something can't be built now
   (external dep/creds), make it config-selected + fail-fast and log it as a backlog task + an ARCHITECTURE_GATES
   "deferred" line, not a code marker. Build **all 18 SRS §6 domains** to depth, **backend-first**; **UI is a
   separate designer's job** — build the APIs, don't block on screens.

## Standards spine

NIST CSF 2.0 · NIST SP 800-61r3 · MITRE ATT&CK · OCSF · Sigma · STIX/TAXII · CIS v8.1 · FIRST TLP 2.0 · Zero Trust.
See [knowledge/standards-references.md](knowledge/standards-references.md) — **note the caveat that NIST SP 800-61
guidance must be re-verified against current NIST publications.**

## Expert-review gate (important)

The SRS is a comprehensive **draft**. It explicitly requires validation by a senior cybersecurity architect, SOC
operations lead, cloud security architect, and privacy/regulatory counsel before being treated as final for
implementation. Do not present the docs as production-signed-off. Flag security-sensitive design choices for
expert review rather than deciding them unilaterally.

## Known environment gaps (for future sessions)

- **PDF text extraction was unavailable** when this base was built (no poppler / PDF library), so any source
  PDFs under `docs/source/` are represented by summaries/pointers rather than full extractions. If you have PDF
  tooling, extract the source PDF and replace the derived markdown.
- `.docx`/`.xlsx` were extracted via ZIP/XML parsing (PowerShell .NET). The SRS markdown flattens Word tables to
  sequential lines; the `.docx`/`.pdf` in `docs/source/` remain authoritative.
