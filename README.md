# Nirvet — SOC-as-a-Service Platform

> **Nirvet** · *Network Intelligence, Risk Visibility & Event Triage*

**Nirvet** is a modular **Cyber Security Operations Platform** — a native SOC operating layer packaged as SOCaaS,
MDR, Managed XDR, Sovereign SOC, Enterprise Private SOC, and MSSP white-label. This repository is currently the
**planning & knowledge base** for the venture: the full requirements/design document suite, organised so any
teammate — human or AI agent — can get oriented fast and build from a single source of truth.

> **Status:** Working scaffold — the backend runs. Go API + ingest worker + Next.js console + Postgres, with
> the full SOC value loop, all engines, cloud-portable infra, tests and Docker/CI. Not production (pre-go-live
> security-architect review pending). The `docs/` here are the requirements/design source of truth; the code lives
> in `backend/`, `frontend/`, `deploy/`. See [RUNNING.md](RUNNING.md) for how to run and what's verified.

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
└─ build/adr/           ← Architecture Decision Records (multi-tenancy, event store, ingestion, vault)
```

## Codebase (scaffold — runs locally)

- **Stack:** Go (entity→repo→usecase→handler) · Next.js + TypeScript · PostgreSQL · Render/Vercel → GCP.
- **Working today:** the SOC value loop end-to-end (tenant → login → ingest → normalize → detect → alert →
  incident) with **Postgres RLS tenant isolation** proven across tenants. See [RUNNING.md](RUNNING.md).
- **Scaffolded (interfaces + stubs):** detection, SOAR, AI copilot, threat-intel, connectors, reporting,
  compliance, billing, notify — structured so they slot in without re-architecting.
- **Governed by** the four ADRs in [build/adr/](build/adr/).

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
