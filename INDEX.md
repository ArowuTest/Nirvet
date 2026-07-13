# INDEX — Nirvet artifact catalogue

> **Nirvet** · *Network Intelligence, Risk Visibility & Event Triage* — SOC-as-a-Service platform.

Every artifact in this project: its markdown (agent-readable), its immutable source, and a one-line summary.
**Source of truth = the files in `docs/source/`.** Markdown is a faithful derived copy.

## Primary spec

| Doc | Summary | Markdown | Source |
|---|---|---|---|
| **SRS** | Full Software Requirements Specification — 20 sections; canonical/deepest spec (functional 6.1–6.18, data, integration, AI, IR, compliance, NFR, security, journeys, packages, roadmap, testing, traceability, appendices). | [00_SRS.md](docs/markdown/00_SRS.md) | `Best_in_Class_Cyber_Security_SOC_Platform_SRS.docx` + `.pdf` |

## Document suite (concise)

| # | Summary | Markdown | Source |
|---|---|---|---|
| 01 | Master product vision, customer segments, deployment models, product modules, FR-001–012, NFR-001–010, service tiers, MVP definition. | [01_master_requirements.md](docs/markdown/01_master_requirements.md) | `01_SOC_Platform_Master_Requirements.docx` + `.pdf` |
| 02 | Technical architecture — 11-layer reference arch, core data domains, OCSF-inspired event model, integration patterns, phased connector catalogue, security controls, DevSecOps environments. | [02_technical_architecture.md](docs/markdown/02_technical_architecture.md) | `02_SOC_Platform_Technical_Architecture.docx` + `.pdf` |
| 03 | SOC operating model — roles, 24/7 coverage stages, severity P1–P4, incident lifecycle, authority-to-act, core playbooks, onboarding workflow, KPIs & governance. | [03_operating_model_and_playbooks.md](docs/markdown/03_operating_model_and_playbooks.md) | `03_SOC_Operating_Model_and_Playbooks.docx` + `.pdf` |
| 04 | AI SOC, detection engineering & SOAR — AI capabilities & guardrails, detection lifecycle & catalogue, initial detection use-case library, SOAR workflow requirements, example playbook. | [04_ai_detection_and_soar.md](docs/markdown/04_ai_detection_and_soar.md) | `04_AI_Detection_and_SOAR_Specification.docx` + `.pdf` |
| 05 | Commercial packaging, entitlements/controls, 6-phase implementation roadmap, governance forums, risk register, due-diligence checklist, Ghana reference wrapper. | [05_commercial_roadmap_governance_risk.md](docs/markdown/05_commercial_roadmap_governance_risk.md) | `05_Commercial_Roadmap_Governance_and_Risk.docx` + `.pdf` |
| 06 | Build backlog — 16 epics / 64 stories (36 MVP, 20 V1, 8 V2), integration roadmap (16), playbooks (6), detection use cases (10), dashboard summary. | [06_build_backlog.md](docs/markdown/06_build_backlog.md) | `06_SOC_Platform_Build_Backlog.xlsx` |

## Knowledge (synthesized quick-reference)

| File | Summary |
|---|---|
| [knowledge/platform-overview.md](knowledge/platform-overview.md) | One-page "start here" — what we're building, governing principle, native-vs-integrated, phasing, standards. |
| [knowledge/requirements-register.md](knowledge/requirements-register.md) | Consolidated FR/NFR IDs + backlog mapping + the 6 cross-cutting invariants + link to SRS §6 capability domains. |
| [knowledge/standards-references.md](knowledge/standards-references.md) | Standards list with usage & links; the NIST SP 800-61 caveat; the standing expert-validation note. |

## Entry points

| File | Purpose |
|---|---|
| [README.md](README.md) | Human entry point: overview, layout, status. |
| [CLAUDE.md](CLAUDE.md) | Agent operating guide: read order, conventions, product invariants, environment gaps. |
| [RUNNING.md](RUNNING.md) | How to run the app locally + what's verified. |
| [build/README.md](build/README.md) | Implementation entry → `../backend`, `../frontend`, `../deploy`. |
| [build/adr/](build/adr/) | Architecture Decision Records (0001–0005). |
| [build/ARCHITECTURE_GATES.md](build/ARCHITECTURE_GATES.md) · [build/BACKEND_AUDIT.md](build/BACKEND_AUDIT.md) | Design gates + audit findings. |

## Code (runs today)

`backend/` — Go API + ingest worker + migrations (29 packages, tests, Dockerfile).
`frontend/` — Next.js + TypeScript SOC console. `deploy/` — docker-compose, render.yaml.

## Source inventory (`docs/source/`, immutable)

13 files: docs 01–05 (`.docx` + `.pdf` each = 10), SRS (`.docx` + `.pdf`), backlog (`.xlsx`).
