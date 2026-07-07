# Requirements register — FR / NFR

Consolidated requirement IDs from `docs/markdown/01_master_requirements.md`. The **deeper functional detail**
lives in the SRS §6 (capability domains 6.1–6.18) and its §19 traceability matrix — see
[00_SRS.md](../docs/markdown/00_SRS.md). Backlog stories that implement these are in
[06_build_backlog.md](../docs/markdown/06_build_backlog.md).

## Functional requirements (FR)

Pattern: *"The platform shall provide configurable **[area]** functionality with tenant-aware permissions, audit
trail, lifecycle status, and export/API support."*

| ID | Area | Release | Backlog epic(s) |
|---|---|---|---|
| FR-001 | Customer onboarding | MVP | E01 Tenant & Customer Management |
| FR-002 | Asset inventory | MVP | E15-adjacent / SRS §6.15 |
| FR-003 | Log ingestion | MVP | E03 Ingestion & Normalisation, E09 Collectors |
| FR-004 | Alert management | MVP | E04 Alert Queue & Triage |
| FR-005 | Incident management | MVP | E05 Incident Case Management |
| FR-006 | Investigation timeline | MVP | E05 (US-018) |
| FR-007 | Evidence handling | MVP | E06 Evidence & Audit Trail |
| FR-008 | SLA management | MVP | E01 / E05 |
| FR-009 | SOAR playbooks | V1 | E12 SOAR Playbooks & Approvals |
| FR-010 | Reporting | V1 | E07 Customer Portal & Reporting |
| FR-011 | Compliance packs | V1 | E06 / SRS §11 |
| FR-012 | Admin configuration | V1 | SRS §6.18 Platform Administration |

> **Note:** doc 01 is the concise register. The SRS expands functional requirements into 18 capability domains
> (§6.1 Tenant/Org/Account, §6.2 IAM/Session, §6.3 Portals/Dashboards, §6.4 Ingestion/Connector Framework,
> §6.5 Normalization/Enrichment/Entity Resolution, §6.6 Detection Engineering, §6.7 Correlation/Risk Scoring,
> §6.8 Alert/Incident/Case, §6.9 Investigation Workbench/Timeline/Graph, §6.10 Threat Intel, §6.11 SOAR,
> §6.12 AI Copilot/Agentic Investigation, §6.13 Reporting/Evidence, §6.14 Compliance/Control Mapping,
> §6.15 Asset/Identity/Vuln/Exposure, §6.16 Notification/Collaboration, §6.17 Packages/Entitlements/Billing,
> §6.18 Platform Admin/Feature Flags). Use the SRS when writing detailed acceptance criteria.

## Non-functional requirements (NFR)

| ID | Category | Requirement |
|---|---|---|
| NFR-001 | Security | Tenant data isolated logically; encryption in transit and at rest. |
| NFR-002 | Availability | 99.9%+ for standard tiers; higher for CII/dedicated. |
| NFR-003 | Auditability | Immutable audit logs for all admin/analyst/AI/integration/playbook actions. |
| NFR-004 | Scalability | Scale by tenant, event volume, connector volume, analyst users, reporting. |
| NFR-005 | Performance | Priority alerts appear in analyst queue within agreed latency. |
| NFR-006 | Data residency | Tenant-level residency and retention configurable by deployment/contract. |
| NFR-007 | Observability | Components emit metrics, logs, traces to monitor platform security & reliability. |
| NFR-008 | Extensibility | Connector framework adds source/action integrations without rebuilding core. |
| NFR-009 | Safety | Automated containment controlled by tenant authority-to-act and approval rules. |
| NFR-010 | Maintainability | Major modules ship with automated tests, API docs, deployment scripts. |

## Cross-cutting invariants (apply to every feature)

These recur across the SRS and must hold for **every** capability, not just where named:

1. **Tenant isolation** — every query, object, file, vector embedding, and action is tenant-scoped; isolation
   tested in CI/CD. (NFR-001, SRS §13)
2. **Audit everything** — immutable append-only audit for login/admin/analyst/AI/SOAR. (NFR-003)
3. **Authority-to-act gating** — no destructive/business-impacting response without policy + approval. (NFR-009)
4. **AI is assistive** — AI cannot execute containment; only SOAR under approval. (doc 04 §3)
5. **Evidence is defensible** — raw event recoverable, hashed, chain-of-custody. (doc 02 §4)
6. **Definition of Done** — feature is portal/API-exposed, tenant-scoped, audited, tested, documented.
   (backlog acceptance-criteria template; SRS §18.3)
