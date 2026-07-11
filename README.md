# Nirvet — SOC-as-a-Service Platform

> **Nirvet** · *Network Intelligence, Risk Visibility & Event Triage*

**Nirvet** is a modular **Cyber Security Operations Platform** — a native SOC operating layer packaged as SOCaaS,
MDR, Managed XDR, Sovereign SOC, Enterprise Private SOC, and MSSP white-label. This repository holds both the
built platform (`backend/`, `frontend/`) and its requirements/design source of truth (`docs/`), organised so any
teammate — human or AI agent — can get oriented fast.

> **Status:** Feature-complete-for-launch backend, in a production-hardening phase. All 18 SRS §6 domains are
> implemented (not stubs), the SOC value loop runs end-to-end, and the codebase has been through three
> independent security reviews plus remediation (0 Critical/High outstanding). Go API + ingest worker + Next.js
> console + Postgres (98 migrations). **Not yet production:** the go-live cloud adapters (GCS object store, Cloud
> KMS, Pub/Sub) and the customer-facing UI/portal are the remaining pre-go-live work — see the ADRs and
> [RUNNING.md](RUNNING.md). The `docs/` remain the canonical requirements/design source; on any conflict, source wins.

## Start here

1. **[knowledge/platform-overview.md](knowledge/platform-overview.md)** — one-page orientation (what we're
   building, the governing principle, phasing, standards).
2. **[INDEX.md](INDEX.md)** — catalogue of every document (source file + markdown + summary).
3. **[docs/markdown/00_SRS.md](docs/markdown/00_SRS.md)** — the full Software Requirements Specification (the
   deepest, canonical spec).

## Layout

```
nirvet/
├─ README.md            ← you are here
├─ RUNNING.md           ← how to run the app locally + what's verified
├─ CLAUDE.md            ← operating guide for AI agents (read before working here)
├─ INDEX.md             ← catalogue of all design artifacts
├─ backend/             ← Go API + ingest worker + migrations (the platform)
├─ frontend/            ← Next.js + TypeScript SOC console
├─ deploy/              ← docker-compose (local Postgres), infra
├─ docs/
│  ├─ source/           ← IMMUTABLE original files (.docx / .pdf / .xlsx) — never edit
│  └─ markdown/         ← agent-readable conversions (00_SRS + 01–06 + Ghana)
├─ knowledge/           ← synthesized quick-reference (overview, requirements register, standards)
└─ build/adr/           ← Architecture Decision Records (6: multi-tenancy, event store, ingestion, vault, cloud-portability, canonical schema)
```

## Codebase

- **Stack:** Go (entity→repo→usecase→handler) · Next.js + TypeScript · PostgreSQL (RLS) · Render/Vercel now →
  GCP/sovereign at go-live (ADR-0005).
- **SOC value loop, end-to-end and live:** tenant → login → ingest → normalize → detect → correlate → alert →
  incident → SOAR, with **Postgres RLS tenant isolation** proven across tenants. See [RUNNING.md](RUNNING.md).
- **Built (not stubs):** detection (Sigma + CEL, lifecycle, MITRE), correlation + risk scoring, SOAR with real
  Defender/Entra containment (four-eyes, dormant-by-default, protected-target guards), AI copilot + admin-
  configurable providers, threat-intel (STIX 2.1), incident/case management, evidence + signed chain-of-custody,
  vulnerability/exposure, reporting (+ zero-egress PDF), compliance, billing (umbrella accounts), notifications
  (+ in-app inbox), IAM (MFA/OIDC/SAML/API-keys/session-revocation/admin password-reset/per-user kill-switch),
  connectors (MS Graph/Defender/Entra pull+action, mTLS syslog, ServiceNow/Jira), and the Ghana operator layer
  (fleet oversight, bulk onboarding, white-label branding).
- **Portable by construction (ADR-0005):** relational/telemetry/object/queue/vault/LLM each sit behind a platform
  interface. Postgres backs the MVP; the **ClickHouse** telemetry store is implemented; the **GCS**, **Cloud
  KMS**, and **Pub/Sub** go-live adapters are in progress.
- **Governed by** the six ADRs in [build/adr/](build/adr/).

## The core idea (in one line)

**Build a native SOC operating layer first — integration-first, but not integration-dependent.** We don't rebuild
Defender/CrowdStrike/firewalls; Nirvet is the platform *above* them that ingests, correlates, investigates,
automates, reports, and manages incidents across a customer's tools.

## The name

**Nirvet** = **N**etwork **I**ntelligence · **R**isk **V**isibility · **E**vent **T**riage — the three things the
platform does over a customer's estate: sees the telemetry, surfaces the risk, and triages what matters.

## Document suite

| # | Document | Markdown |
|---|---|---|
| — | Full SRS (20 sections, canonical) | [00_SRS.md](docs/markdown/00_SRS.md) |
| 01 | Master Product, Functional & NFR Requirements | [01](docs/markdown/01_master_requirements.md) |
| 02 | Technical Architecture, Data Model & Integrations | [02](docs/markdown/02_technical_architecture.md) |
| 03 | Operating Model, Roles, SLAs & Playbooks | [03](docs/markdown/03_operating_model_and_playbooks.md) |
| 04 | AI SOC, Detection Engineering & SOAR | [04](docs/markdown/04_ai_detection_and_soar.md) |
| 05 | Commercial Packaging, Roadmap, Governance & Risk | [05](docs/markdown/05_commercial_roadmap_governance_risk.md) |
| 06 | Build Backlog (16 epics / 64 stories) | [06](docs/markdown/06_build_backlog.md) |

## Provenance

The document suite originated from a structured design discussion (July 2026) and was refined into a full SRS.
Originals are preserved verbatim in `docs/source/`. The markdown in `docs/markdown/` is a faithful conversion for
readability and search; **on any conflict, the source files win.** The SRS itself is a comprehensive *draft* that
requires sign-off by senior cyber/SOC/cloud/privacy experts before it is treated as final for implementation —
see [knowledge/standards-references.md](knowledge/standards-references.md).
