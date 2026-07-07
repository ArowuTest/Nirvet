# SOC Platform — Master Product, Functional & Non-Functional Requirements

> Clean markdown of `docs/source/01_SOC_Platform_Master_Requirements.docx` (source of truth = the `.docx`/`.pdf`).
> Part of a build-and-operate pack for a modular Cyber Security Operations Platform capable of
> SOC-as-a-Service, MDR, Managed XDR, sovereign SOC, enterprise private SOC, and MSSP white-label deployments.

## 1. Executive product vision

The platform is a **modular Cyber Security Operations Platform**, not a single-country SOC dashboard. It is
intended to power SOC-as-a-Service, MDR, Managed XDR, sovereign/local SOC deployments, enterprise private SOCs,
and MSSP white-label offerings. It provides native SOC functions while integrating with customer security
controls and IT systems.

**Strategic design principle** — Build a native SOC operating layer first, then add external integrations in
controlled phases. The product must work with basic syslog/API/webhook feeds and become more powerful as
Microsoft, EDR, cloud, firewall, identity, ticketing and collaboration systems are connected.

## 2. Target customer segments and use cases

| Segment | Primary need | Platform proposition |
|---|---|---|
| SMEs and mid-market | Affordable 24/7 monitoring without building a SOC | Essential Monitor and Standard SOCaaS with Microsoft, firewall syslog, endpoint and reporting. |
| Banks and fintechs | Identity, endpoint, cloud and payment-adjacent monitoring with compliance evidence | Advanced MDR/Managed XDR with strict audit trails, SLA, incident evidence and executive reporting. |
| Telecoms and utilities | High-volume monitoring, critical infrastructure resilience and incident coordination | Critical Infrastructure tier with custom detections, senior escalation, IR retainer and sector dashboard. |
| Government and regulators | Sovereign data residency, compliance evidence and sector oversight | Sovereign SOC deployment with country-specific compliance packs and optional central buyer dashboard. |
| Enterprise private SOC | Dedicated SOC platform for in-house security team | Private tenant/instance with admin, analyst workbench, playbooks and integrations. |
| MSPs/MSSPs | White-label security operations platform | Partner portal, customer sub-tenancy, branding, reseller billing and shared analyst workflows. |

## 3. Deployment models

| Model | Description | When to use |
|---|---|---|
| Shared SaaS | Multi-tenant cloud platform operated by the provider. | SMEs, mid-market, rapid onboarding, lower cost. |
| Sovereign cloud / local hosting | Data-resident platform deployed in-country or approved jurisdiction. | Government, CII, regulated sectors, public-sector anchor clients. |
| Dedicated customer instance | Single-tenant instance with isolated storage and optional dedicated compute. | Banks, telecoms, large enterprises, data sovereignty requirements. |
| Hybrid collector model | Customer-side collector forwards normalized events/alerts to the platform. | Clients with sensitive data, bandwidth constraints, or internal log retention requirements. |
| White-label MSSP mode | MSSP can onboard and manage its own customers under its brand. | Channel expansion and regional partner scaling. |

## 4. Product modules

| Module | Core requirements |
|---|---|
| Tenant and customer management | Customer records, service tier, retention, data residency, SLAs, contacts, escalation matrix, billing terms and integration inventory. |
| Identity, access and permissions | RBAC/ABAC, MFA, SSO, privileged admin roles, analyst roles, customer roles, API tokens and separation of duties. |
| Alert ingestion and normalization | APIs, syslog, webhooks, file ingestion, connector polling, schema mapping, deduplication and enrichment queues. |
| Analyst workbench | Alert queue, severity, customer context, timeline, entity graph, evidence, notes, task assignment and escalation. |
| Incident case management | Case creation, classification, impacted entities, severity, SLA, status, evidence, approvals, customer communication and closure report. |
| Detection engineering | Rule catalogue, rule lifecycle, Sigma support, MITRE mapping, tuning, false-positive feedback and coverage heatmaps. |
| SOAR and playbooks | Approval-based response workflows, containment actions, notification templates, ticket sync and post-action audit. |
| Threat intelligence | IOC enrichment, TLP handling, STIX/TAXII support, MISP/OTX/commercial feed integration and watchlists. |
| AI SOC assistant | Alert summarisation, correlation recommendations, attack timeline, report drafting, detection tuning suggestions and analyst copiloting. |
| Reporting and compliance evidence | Executive dashboards, monthly reports, SLA reports, evidence packs, regulator-ready incident summaries and audit exports. |
| MSP/white-label portal | Partner hierarchy, delegated administration, branded reports, reseller pricing and sub-customer management. |
| Billing and subscription | Service tiers, log volume entitlements, overage tracking, add-ons, invoices and revenue reporting. |

## 5. Functional requirements

Each requirement: *"The platform shall provide configurable **[area]** functionality with tenant-aware
permissions, audit trail, lifecycle status, and export/API support."*

| ID | Area | Release |
|---|---|---|
| FR-001 | Customer onboarding | MVP |
| FR-002 | Asset inventory | MVP |
| FR-003 | Log ingestion | MVP |
| FR-004 | Alert management | MVP |
| FR-005 | Incident management | MVP |
| FR-006 | Investigation timeline | MVP |
| FR-007 | Evidence handling | MVP |
| FR-008 | SLA management | MVP |
| FR-009 | SOAR playbooks | V1 |
| FR-010 | Reporting | V1 |
| FR-011 | Compliance packs | V1 |
| FR-012 | Admin configuration | V1 |

## 6. Non-functional requirements

| ID | Category | Requirement |
|---|---|---|
| NFR-001 | Security | All tenant data must be isolated logically and protected with encryption in transit and at rest. |
| NFR-002 | Availability | Production service target should be 99.9%+ for standard tiers and higher for critical infrastructure/dedicated deployments. |
| NFR-003 | Auditability | All administrative, analyst, AI, integration and playbook actions must create immutable audit logs. |
| NFR-004 | Scalability | Architecture must scale by tenant, event volume, connector volume, analyst users and report generation. |
| NFR-005 | Performance | Priority alerts should appear in the analyst queue within agreed latency after receipt/collection. |
| NFR-006 | Data residency | Tenant-level residency and retention policies must be configurable by deployment and contract. |
| NFR-007 | Observability | Platform components must emit metrics, logs and traces to monitor own platform security and reliability. |
| NFR-008 | Extensibility | Connector framework must allow new source/action integrations without rebuilding the core platform. |
| NFR-009 | Safety | Automated containment must be controlled by tenant-specific authority-to-act and approval rules. |
| NFR-010 | Maintainability | All major modules must include automated tests, API documentation and deployment scripts. |

## 7. Service tiers and entitlement design

| Tier | Typical customer | Included scope | Hard limits to define contractually |
|---|---|---|---|
| Essential Monitor | Small agency/SME | Core alert receipt, Microsoft 365, basic endpoint/firewall syslog, monthly report. | Assets, log volume, retention, included integrations, report frequency. |
| Standard SOCaaS | Mid-market/MDA | 24/7 monitoring, identity, endpoint, server/firewall logs, case management, quarterly review. | SLA window, retention, included playbooks, volume caps. |
| Advanced MDR | Regulated entity | EDR/XDR integrations, threat intel, response playbooks, tabletop exercise, compliance pack. | IR hours, detection customization, number of integrations. |
| Critical Infrastructure | Bank/telco/utility | Priority queue, custom detection, senior analyst escalation, board dashboard, IR retainer. | Authority-to-act, escalation times, data residency, retention. |
| Enterprise/Sovereign/White-label | Cluster buyer/MSSP/large enterprise | Dedicated/sovereign/white-label options, central dashboard, multi-year commitments. | Custom pricing, onboarding factory, scope boundaries, support model. |

## 8. MVP definition

The MVP should prove the platform can onboard tenants, ingest alerts/logs, triage security events, create
incident cases, provide analyst and customer visibility, and generate credible reports — focusing on a narrow
integration set rather than every connector.

| MVP capability | Minimum acceptance outcome |
|---|---|
| Tenant portal and admin portal | Provider can create customers, users, service tier, SLAs and escalation contacts. |
| Ingestion API/webhook/syslog | Platform can receive test alerts/events and normalize them into a standard event model. |
| Microsoft-focused connectors | M365/Entra/Defender initial connector patterns or import stubs are working. |
| Alert queue | Analyst can view, filter, assign, prioritise and convert alerts into incidents. |
| Case management | Incident can move from New → Triage → Investigating → Contained → Closed. |
| AI summarisation | AI can summarise the alert and draft an investigation note with citation to available evidence. |
| Reporting | Monthly customer report and incident closure report can be generated. |
| Audit trail | Admin, analyst and playbook actions are logged with user, timestamp and tenant. |

## Reference standards and sources

- **NIST Cybersecurity Framework 2.0** — https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final
- **NIST SP 800-61 Revision 3** (Incident Response Recommendations) — https://csrc.nist.gov/pubs/sp/800/61/r3/final
- **MITRE ATT&CK** Enterprise Matrix — https://attack.mitre.org/matrices/enterprise/
- **OCSF** (Open Cybersecurity Schema Framework) — https://ocsf.io/
- **Sigma** Detection Format — https://sigmahq.io/docs/basics/rules.html
- **OASIS STIX/TAXII** — https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti
- **CIS Critical Security Controls v8.1** — https://www.cisecurity.org/controls/v8-1
- **FIRST Traffic Light Protocol 2.0** — https://www.first.org/tlp/
