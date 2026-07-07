# Nirvet — platform overview (start here)

> **Nirvet** · *Network Intelligence, Risk Visibility & Event Triage*

One-page orientation to Nirvet, the SOC-as-a-Service platform. For detail, follow the links into `../docs/markdown/`.

## What we are building

**Nirvet** is a **modular Cyber Security Operations Platform** — a native SOC operating layer that ingests,
correlates, investigates, automates, reports on, and manages security incidents across many customer tools. It is packaged
as several commercial models from the **same core product**:

- **SOCaaS** (SOC-as-a-Service) · **MDR** (Managed Detection & Response) · **Managed XDR**
- **Sovereign SOC** (in-country / data-resident) · **Enterprise Private SOC** · **MSSP White-label**

We are **not** rebuilding Defender / CrowdStrike / firewalls / identity providers. Those are **data sources and
action channels**. Our value is the **SOC platform layer above them**.

## The one design principle that governs everything

> **Native SOC operating layer first — integration-first, but not integration-dependent.**

The platform must work with only basic syslog/API/webhook feeds, and get more powerful as Microsoft, EDR, cloud,
firewall, identity, ticketing and collaboration systems are connected. It must never collapse because a customer
lacks a specific vendor tool.

## What the platform owns (native) vs integrates

| Native (our product) | Integrated (customer's tools) |
|---|---|
| Portals (customer/admin/analyst/MSP), tenant mgmt, RBAC/SSO | Microsoft 365, Entra ID, Defender |
| Alert queue, incident/case mgmt, investigation timeline, evidence locker | CrowdStrike, SentinelOne, Sophos (EDR) |
| Detection engineering (Sigma, MITRE), correlation, risk scoring | Fortinet, Palo Alto, Cisco, Zscaler, Cloudflare |
| SOAR playbooks & approvals, authority-to-act enforcement | AWS, Azure, GCP, Google Workspace |
| AI SOC copilot (summaries, timelines, tuning) with guardrails | Okta (identity), vuln scanners, email security |
| Reporting, compliance evidence packs, executive dashboards | Jira, ServiceNow (ticketing), Slack, Teams |
| Billing/subscription, SLA tracking, MSP white-label | Syslog, webhooks, customer APIs (generic) |

## Core building blocks

- **Reference architecture** — 11 layers: experience → API → identity → ingestion → event processing → storage →
  detection → SOAR → AI → reporting → platform ops. See [architecture](../docs/markdown/02_technical_architecture.md).
- **Normalized event model** — OCSF-inspired schema (metadata / classification / actor / target / action-outcome /
  threat-context / evidence) while retaining raw evidence.
- **Operating model** — SOC roles (Director → Shift Lead → T1/T2/T3 → Detection Eng → IR Lead), severity **P1–P4**,
  8-stage incident lifecycle, **authority-to-act** modes (observe → approval → pre-authorised → emergency).
  See [operating model](../docs/markdown/03_operating_model_and_playbooks.md).
- **AI is human-in-the-loop** — assists, never autonomously executes destructive/containment actions. Only the
  SOAR engine acts, under approval policy. See [AI/detection/SOAR](../docs/markdown/04_ai_detection_and_soar.md).

## Phasing at a glance

| Phase | Focus | Integrations |
|---|---|---|
| **MVP** (mo. 2–4) | Tenant/admin portals, ingestion, alert queue, case mgmt, basic reports, AI summarise | M365, Entra, Defender, syslog, webhook/API, Jira/ServiceNow |
| **V1 / SOCaaS + MDR/XDR** (mo. 5–15) | Production tenancy, SLAs, analyst workbench, detection eng, SOAR, threat intel | AWS, Azure, Fortinet, Palo Alto, CrowdStrike, SentinelOne, vuln scanners |
| **V2 + AI SOC** (mo. 12–20) | AI investigation/tuning, exec reporting, connector marketplace | Okta, Cloudflare, Zscaler, GCP, email security |
| **Enterprise/Sovereign/White-label** (mo. 18–36) | Dedicated/sovereign deployments, MSP hierarchy, regulator dashboards | Sector/banking/telecom/OT feeds, regulator APIs |

Backlog: **64 stories / 16 epics** (36 MVP, 20 V1, 8 V2). See [backlog](../docs/markdown/06_build_backlog.md).

## Standards spine

NIST CSF 2.0 · NIST SP 800-61r3 · MITRE ATT&CK · OCSF · Sigma · STIX/TAXII · CIS Controls v8.1 · FIRST TLP 2.0 ·
Zero Trust. See [standards-references](standards-references.md).

## Where the truth lives

- **Deepest / canonical:** the **SRS** ([00_SRS.md](../docs/markdown/00_SRS.md)) — 20 sections, full functional
  (6.1–6.18), data, integration, AI, IR, compliance, NFR, security, roadmap, testing, traceability.
- **Concise suite:** docs 01–05 (requirements, architecture, operating model, AI/SOAR, commercial).
- **Immutable originals:** `../docs/source/` (`.docx`/`.pdf`/`.xlsx`) — never edit these.
- **Status:** planning / knowledge-base stage. No code yet — `../build/` is a placeholder.
