# Best-in-Class Cyber Security Operations Platform — Full SRS

> **Agent-readable extraction.** Faithful full-text extraction from `docs/source/Best_in_Class_Cyber_Security_SOC_Platform_SRS.docx`.
> The `.docx` / `.pdf` in `docs/source/` remain the source of truth. Word tables are flattened to sequential lines (header cells then row cells).
> Version 1.0, dated 07 July 2026. Classification: Confidential — Build Planning.

## Section index

- 1. Executive Truth Review and Scope
- 2. Product Vision, Objectives and Success Measures
- 3. Stakeholders, User Classes and Personas
- 4. Platform Operating Models and Deployment Models
- 5. System Context and High-Level Architecture
- 6. Functional Requirements by Capability Domain (6.1–6.18)
- 7. Data, Schema, Storage and Retention Requirements
- 8. Integration and Connector Requirements
- 9. AI SOC, Detection Engineering and SOAR Requirements
- 10. Incident Response, SOC Operations and Service Management Requirements
- 11. Compliance, Regulatory Evidence and Governance Requirements
- 12. Non-Functional Requirements
- 13. Security, Privacy and Multi-Tenancy Requirements
- 14. User Journeys and Use Cases
- 15. Service Packages, Entitlements and Commercial Guardrails
- 16. MVP, V1, V2 and Enterprise Roadmap
- 17. Implementation Plan and Build Governance
- 18. Testing, Validation and Acceptance Criteria
- 19. Requirements Traceability Matrix
- 20. Appendices: Playbooks, Detection Use Cases, Data Dictionary, Backlog Seeds

---


BEST-IN-CLASS CYBER SECURITY OPERATIONS PLATFORM
Full Software Requirements Specification (SRS)
SOCaaS | MDR | Managed XDR | Sovereign SOC | Enterprise Private SOC | MSSP White-Label
Prepared for: FS S / Platform Venture Planning
Version: 1.0 - Full Requirements Draft
Date: 07 July 2026
Classification: Confidential - Build Planning

Document Control
Item
Detail
Document purpose
This SRS defines the complete functional, non-functional, security, operational, data, integration, AI, compliance, and delivery requirements for a best-in-class Cyber Security Operations Platform.
Truth position
This document treats previous proposal material as a market/use-case reference only. The platform scope is intentionally broader than any single Ghana, Nigeria, UK, public-sector, financial-services, or managed-service deployment.
Intended users
Founders, product owners, Developer coding agents, senior engineers, cybersecurity architects, SOC leaders, detection engineers, cloud/DevSecOps teams, investors, procurement teams, and implementation partners.
Build approach
Use Developers as engineering accelerators, but require expert cyber architecture, senior engineering review, secure configuration, detection tuning, operational validation, and managed SOC governance before commercial launch.
Status
Comprehensive draft. Requires final validation by a senior cybersecurity architect, SOC operations lead, cloud security architect, privacy/regulatory counsel, and target-client representatives.

Revision History
Version
Date
Author/Owner
Summary
1.0
2026-07-07
ChatGPT for FS S
Full SRS created from platform vision, reference concept paper, and best-practice SOC/MDR/XDR design patterns.

Reference Frameworks and Standards Used
The SRS is aligned to widely used security operations and cyber risk references, including NIST CSF 2.0, NIST incident handling guidance, MITRE ATT&CK, OCSF, Sigma, STIX/TAXII, CIS Controls, FIRST TLP, and Zero Trust principles. These references are not copied into the product as rigid constraints; they guide taxonomy, reporting, evidence, control coverage, detection language, intelligence exchange, and operating model decisions.
Reference
Use in SRS
Source
NIST CSF 2.0
Govern, Identify, Protect, Detect, Respond, Recover outcome mapping; board/regulator reporting; cyber risk maturity views.
NIST CSWP 29, 2024; https://www.nist.gov/cyberframework
NIST SP 800-61 Rev. 2 / successor guidance
Incident handling lifecycle, triage, containment, eradication, recovery, lessons learned. Rev. 2 is archived/withdrawn by NIST, so final implementation should verify current successor guidance.
https://csrc.nist.gov/pubs/sp/800/61/r2/final
MITRE ATT&CK Enterprise
Tactic/technique mapping, detection coverage, threat-hunting library, case timeline enrichment.
https://attack.mitre.org/
OCSF
Vendor-neutral event normalization strategy for security events, entities, activities, categories, and extensions.
https://ocsf.io/
Sigma
Portable detection rule authoring format and detection-as-code governance.
https://sigmahq.io/
STIX/TAXII 2.1
Threat-intelligence objects, indicators, sightings, and exchange mechanism.
https://www.oasis-open.org/standard/taxii-version-2-1/
CIS Controls
Baseline customer control mapping, audit readiness, and managed service evidence packs.
https://www.cisecurity.org/controls
FIRST TLP 2.0
Information-sharing classification for intelligence and incident communications.
https://www.first.org/tlp/




## 1. Executive Truth Review and Scope

### 1.2 Product Scope
The system shall be a modular Cyber Security Operations Platform capable of operating as a SaaS platform, managed service platform, sovereign/local SOC platform, enterprise private SOC platform, and MSSP white-label platform. It shall provide native SOC functions while integrating with customer-owned identity, endpoint, cloud, firewall, email, vulnerability, ticketing, messaging, SIEM, and threat intelligence systems.

### 1.3 In Scope
Multi-tenant SOC platform with strong tenant isolation and deployment-mode flexibility.
Customer portal, admin portal, SOC analyst workbench, detection engineering workspace, service management workspace, and executive/regulatory reporting portal.
Alert, log, finding, asset, identity, and vulnerability ingestion through APIs, collectors, syslog, webhooks, batch uploads, and vendor connectors.
Correlation, deduplication, prioritisation, case management, investigation timeline, evidence handling, SLA tracking, and customer approval workflows.
Detection-as-code library, rule testing, tuning workflow, MITRE ATT&CK coverage, and customer-specific baselines.
SOAR playbooks with human-in-the-loop action gating, authority-to-act policy enforcement, and automated evidence capture.
AI analyst copilot, AI investigation assistant, AI report generator, and AI detection tuning assistant with strong controls and audit logs.
Compliance evidence modules configurable for Ghana, Nigeria, UK, financial services, public sector, critical infrastructure, data protection, and internal audit use cases.
Operational requirements for 24/7 SOC, MDR, incident response, threat hunting, customer onboarding, customer success, and service reviews.
Implementation roadmap, backlog seed, test strategy, and traceability matrix.

### 1.4 Out of Scope for Initial Build
Replacing full enterprise EDR products such as Microsoft Defender, CrowdStrike, SentinelOne, Sophos, or equivalent endpoint agents.
Replacing full enterprise firewalls, secure web gateways, CASB/SASE platforms, or identity providers.
Providing unauthorised offensive security tooling, malware deployment, exploit automation, or intrusive testing without explicit customer authority.
Autonomous destructive containment actions unless customer authority-to-act rules and human approval gates explicitly permit them.
Guaranteeing prevention of all breaches. The platform shall provide monitoring, detection, response workflow, evidence, and risk reduction; it cannot guarantee zero incidents.

### 1.5 Definitions
Term
Definition
SOC
Security Operations Centre: people, process, and technology for security monitoring, detection, investigation, response, and reporting.
SOCaaS
SOC-as-a-Service: outsourced SOC capability delivered as a subscription.
MDR
Managed Detection and Response: managed service combining monitoring, investigation, detection engineering, and guided/managed response.
XDR
Extended Detection and Response: integrated detection and response across endpoint, identity, email, network, cloud, and other telemetry.
SOAR
Security Orchestration, Automation and Response: workflow automation, enrichment, action execution, and case orchestration.
Tenant
A customer, business unit, MSP client, or deployment partition with separate users, assets, logs, cases, and policies.
Authority to Act
Contractual and system policy defining which response actions the SOC may execute automatically, with approval, or not at all.
Detection as Code
Version-controlled detection rules, tests, metadata, deployment approvals, and tuning workflows.
Evidence Pack
Structured, exportable evidence set for audit, board, regulator, customer service review, or post-incident reporting.



## 2. Product Vision, Objectives and Success Measures

### 2.1 Product Vision
To build a trusted, modular, AI-assisted Cyber Security Operations Platform that enables organisations and managed security providers to detect, investigate, respond to, evidence, and report cyber threats across fragmented security toolsets, multiple customer segments, and varied regulatory environments.

### 2.2 Strategic Objectives
ID
Objective
OBJ-001
Provide a single operational layer for alerts, incidents, threats, assets, vulnerabilities, identities, evidence, and customer communications.
OBJ-002
Make SOCaaS and MDR commercially viable for organisations that cannot build their own 24/7 SOC.
OBJ-003
Support enterprise-grade and sovereign deployment models without rewriting the product for each country or sector.
OBJ-004
Use AI to accelerate triage, investigation, reporting, and tuning, while keeping containment decisions safe, explainable, and auditable.
OBJ-005
Create configurable service packages with clear entitlements, limits, margins, SLAs, and add-on services.
OBJ-006
Enable expert cybersecurity teams to continuously improve detections, playbooks, coverage, and customer security outcomes.
OBJ-007
Provide board, regulator, audit, and customer evidence without requiring manual spreadsheet-based SOC reporting.
OBJ-008
Deliver a product architecture that can be built in phases by engineering teams and Developers without locking the venture into one vendor stack.


### 2.3 Success Measures
Category
Measure
Target / Design Goal
Security Operations
Mean time to triage Priority 1 alert
< 15 minutes for managed service tiers once onboarded and tuned.
Security Operations
Mean time to customer notification
Within tier-specific SLA and customer communication policy.
Detection Quality
False-positive rate after tuning period
< 20% per tenant for mature rules; monitored by rule and data source.
Platform Reliability
Core platform uptime
99.9% MVP, 99.95% enterprise tier, 99.99% optional dedicated/critical tier.
Data Pipeline
Ingestion delay
Near-real-time for streaming connectors; target < 2 minutes for supported APIs/syslog where source permits.
AI Safety
Ungated high-impact action rate
0. No destructive or business-impacting response action without appropriate policy and approval.
Commercial
Gross margin protection
Package limits and overage billing enforced through system entitlements.
Compliance
Evidence pack availability
100% on-time for regulated tenants with configured compliance templates.
Customer Trust
Auditability
All analyst, system, AI, and automation decisions must be traceable.



## 3. Stakeholders, User Classes and Personas

### 3.1 Stakeholder Groups
Stakeholder
Primary Interest
Platform Implications
Customer CISO / Security Lead
Visibility, response confidence, reporting, evidence, SLA performance.
Executive dashboards, severity transparency, service review packs, approved playbooks, data source health.
Customer IT Admin
Connector setup, remediation tasks, asset context, user account actions.
Guided onboarding, least-privilege integration setup, approval workflows, action audit trail.
SOC Tier 1 Analyst
Fast triage, enrichment, deduplication, clear escalation.
Alert queue, triage forms, AI summary, runbook steps, escalation rules.
SOC Tier 2 Analyst
Deep investigation, timeline, correlated evidence.
Entity graph, raw event access, related alerts, investigation notebook, customer context.
SOC Tier 3 / IR Lead
Major incident command, containment, eradication, forensic evidence.
War room, high-risk action controls, evidence chain, post-incident report.
Detection Engineer
Rule lifecycle, test data, coverage, tuning.
Detection-as-code repository, rule lab, MITRE coverage, deployment workflow.
Threat Intelligence Analyst
Indicators, campaigns, advisories, intelligence sharing.
STIX/TAXII feeds, indicator lifecycle, intel-to-detection workflow, TLP labels.
MSSP Operator
Many customers, white-labeling, entitlements, billing, cross-tenant benchmarking.
Partner hierarchy, tenant templates, package limits, MSP dashboards.
Regulator / Auditor
Evidence, incident timelines, control coverage, governance.
Exportable evidence packs, immutable logs, regulatory dashboards.
Investor / Executive Board
ARR, margin, operational maturity, risk management.
Business KPIs, utilisation, churn, incident trends, audit outcomes.


### 3.2 User Roles
Role
Description
Platform Super Admin
Internal highest-privilege role; configures global system settings, deployment settings, tenant creation, platform health, billing defaults, and emergency controls.
Tenant Admin
Customer-side administrator; manages tenant users, integrations, assets, approval policies, reporting recipients, and compliance settings.
Customer Executive Viewer
Read-only customer role for board-level dashboards, risk trends, SLA reports, and evidence packs.
Customer Technical User
Customer IT/security user who can view alerts, approve actions, provide evidence, and execute customer-side tasks.
SOC Manager
Internal operations lead; manages queues, analyst assignments, quality review, SLAs, shift handover, and escalation.
Tier 1 Analyst
Performs initial triage, enrichment review, false-positive closure, escalation and customer notifications per runbooks.
Tier 2 Analyst
Performs deeper investigation, timeline building, containment recommendations, detection feedback, and incident coordination.
Tier 3 Analyst / Incident Responder
Handles severe incidents, threat hunting, forensic readiness, major containment actions, and post-incident reviews.
Detection Engineer
Creates, tests, deploys, tunes and retires detection content and correlation rules.
Threat Intel Analyst
Manages intel feeds, indicators, advisories, intelligence confidence, TLP classifications, and campaign mapping.
Compliance Manager
Manages regulatory templates, evidence packs, audit requests, policy mapping, and customer assurance outputs.
MSSP Partner Admin
Manages downstream tenants, package templates, white-label settings, partner analysts, and partner reporting.
API Client
Machine role used for integrations, collectors, automation, and customer API access with scoped permissions.



## 4. Platform Operating Models and Deployment Models

### 4.1 Supported Commercial/Operating Models
Model
Description
Key Requirements
SOCaaS
Provider-operated SOC monitoring service for customers that lack internal SOC capability.
Multi-tenant portal, 24/7 queue, clear packages, onboarding factory, SLA evidence.
MDR
Provider-operated detection and response with deeper investigation and guided/managed containment.
EDR/XDR integrations, threat intel, response playbooks, authority-to-act controls.
Managed XDR
Cross-domain detection and response across endpoint, identity, network, email, cloud, vulnerability and threat intel.
Correlation engine, normalized schema, entity graph, high-quality connectors.
Sovereign SOC
Country/local hosted SOC for government, CII, financial services or regulated sectors.
Data residency, local compliance pack, dedicated hosting option, local governance.
Enterprise Private SOC
Dedicated platform instance for one enterprise with optional managed service support.
Dedicated tenancy, SSO, private connectors, custom retention, integration with customer SIEM.
MSSP White-Label
Platform used by managed service partners to serve their clients under their brand.
Partner hierarchy, branding, downstream tenants, reseller billing and analyst partitions.
Hybrid Co-Managed SOC
Customer and provider jointly operate detections and response.
Shared queues, ownership rules, co-managed playbooks, task assignments, split SLAs.


### 4.2 Deployment Models
Deployment Model
When Used
Requirements
Shared SaaS
SMEs, mid-market, standard SOCaaS customers, fast onboarding.
Strong logical tenant isolation, pooled scalable services, package-based limits.
Dedicated SaaS Tenant
Regulated enterprise requiring more isolation but still managed cloud.
Dedicated data stores or namespaces, dedicated keys, advanced logging, configurable retention.
Sovereign Cloud / Local Country Hosting
Government, CII, data residency, national/regional SOC propositions.
Country-specific hosting, legal entity mapping, local backup/DR, local access policy.
Customer Private Cloud
Enterprise/private SOC customers with internal cloud preference.
Deployable stack, infrastructure-as-code, customer-managed network, secure update model.
On-Prem / Air-Gapped Adjacent Collector
Highly sensitive networks or OT environments.
Local collector, buffering, one-way export options, minimal dependencies, strict update controls.
Hybrid Collector Model
Most enterprise deployments.
Customer-side collectors normalize/filter/forward telemetry to platform; raw data residency configurable.


### 4.3 Product Principles
Native core SOC functions must work even when only basic syslog/API/webhook feeds exist.
Integrations increase value but the product must not require every customer to have every tool.
Tenant isolation, evidence integrity, and auditability are foundational; they are not premium extras.
AI must accelerate analysts but cannot become an uncontrolled authority for destructive actions.
The product must support package limits and commercial guardrails from day one.
Every incident, detection, playbook, and customer communication must be traceable to data and decision history.
The architecture must allow vendor substitution: the platform may integrate with Microsoft, CrowdStrike, SentinelOne, Fortinet, Palo Alto, and others without becoming dependent on one ecosystem.


## 5. System Context and High-Level Architecture

### 5.1 System Context
The platform sits above customer tools and provider operations. It ingests alerts, logs, findings, identities, assets, vulnerabilities, and threat intelligence. It normalizes and enriches data, correlates signals, creates incidents, guides analysts, automates approved actions, communicates with customers, and generates evidence and reports.
External Source / Sink
Direction
Examples
Primary Use
Identity providers
Inbound and outbound
Entra ID, Okta, Google Workspace
Identity alerts, risky sign-ins, user context, disable/revoke-session actions.
Endpoint security
Inbound and outbound
Microsoft Defender, CrowdStrike, SentinelOne, Sophos
EDR alerts, device context, isolate host, collect investigation package.
Network/firewall/SASE
Inbound and outbound
Fortinet, Palo Alto, Cisco, Zscaler, Cloudflare
Network detections, blocked traffic, malicious IP/domain actions.
Cloud platforms
Inbound and outbound
AWS, Azure, GCP
CloudTrail/activity logs, IAM changes, GuardDuty/Security Command Center alerts, cloud response tasks.
SIEM/data lakes
Inbound and outbound
Microsoft Sentinel, Splunk, Elastic/OpenSearch, BigQuery
Alert import/export, query delegation, log search, customer existing investment leverage.
Ticketing/ITSM
Outbound and inbound
ServiceNow, Jira, email
Ticket creation, status sync, remediation task tracking.
Messaging
Outbound and inbound
Teams, Slack, email, SMS/WhatsApp gateways
Notifications, approvals, war-room comms, customer escalation.
Threat intelligence
Inbound and outbound
STIX/TAXII, MISP, OTX, commercial feeds
Indicator enrichment, campaign context, detection updates.
Vulnerability tools
Inbound
Tenable, Qualys, Rapid7, Defender Vulnerability Management
Exposure prioritization and incident context.
Customer APIs
Inbound and outbound
Custom business systems, sector platforms
Sector-specific telemetry, evidence, regulatory workflows.


### 5.2 Logical Architecture
The logical architecture shall be divided into presentation, API, identity, tenant management, ingestion, normalization, storage, analytics, detection, correlation, case management, SOAR, AI, reporting, integration, audit, and observability layers. Each layer shall expose clear APIs and event contracts to avoid tight coupling.
Layer
Core Components
Key Requirements
Presentation
Customer portal, analyst workbench, admin portal, executive dashboard, mobile-responsive views.
Role-based navigation, tenant isolation, accessible UI, fast search, export controls.
API Gateway
REST/GraphQL APIs, webhook endpoints, collector APIs, partner APIs.
Authentication, rate limits, idempotency, schema validation, request logging.
Identity & Access
SSO, MFA, RBAC/ABAC, service accounts, API tokens.
Least privilege, tenant boundaries, privileged access review, break-glass controls.
Ingestion
Connectors, syslog collectors, agent/collector, batch import, queue/broker.
Scalable, resumable, source-health monitoring, deduplication, backpressure.
Normalization
Parser framework, OCSF-inspired schema, enrichment pipeline.
Versioned mappings, parser tests, unknown-field preservation.
Storage
Hot event store, incident DB, evidence object store, analytics warehouse, archive.
Encryption, retention policies, query performance, tenant partitioning.
Detection & Correlation
Rule engine, Sigma-like rules, behavioral rules, risk scoring, correlation graph.
Versioning, tests, customer tuning, MITRE mapping, false-positive feedback.
Case Management
Alerts, incidents, tasks, notes, timelines, evidence, SLAs.
Full lifecycle, audit logs, customer visibility controls, assignment workflow.
SOAR
Playbook designer, enrichment steps, action catalog, approval gates.
Safe execution, rollback guidance, authority-to-act enforcement.
AI Layer
AI triage, investigation, summarization, reporting, tuning assistant.
Grounded outputs, citations to evidence, prompt logging, model risk controls.
Reporting
Operational, executive, compliance, service review, regulatory exports.
Templates, scheduling, watermarking, export audit, customer branding.
Observability
Metrics, logs, traces, health checks, synthetic tests.
SLOs, alerting, capacity forecasts, ingestion health.


### 5.3 Recommended Technology Direction
The SRS does not mandate a single stack, but the recommended build pattern is cloud-native, API-first, event-driven, and modular. A likely stack is Next.js/React for portals; Go, Java/Kotlin, or Node/NestJS for services; PostgreSQL for relational data; OpenSearch/ClickHouse/Elastic/Snowflake/BigQuery depending on deployment for event analytics; Kafka/Redpanda/NATS for streaming; Temporal or equivalent for workflows; object storage for evidence; Vault/cloud secrets manager for secrets; Kubernetes or managed containers for deployment; OpenTelemetry/Prometheus/Grafana for observability; and Terraform/OpenTofu for infrastructure as code.


## 6. Functional Requirements by Capability Domain

### 6.1 Tenant, Organisation and Account Management
Req ID
Requirement
Priority
Phase
Acceptance Evidence
TEN-001
The system shall support hierarchical tenant structures including parent customer, subsidiary, department, business unit, MSSP partner, downstream customer, and dedicated sovereign programme.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TEN-002
The system shall isolate users, logs, assets, incidents, evidence, dashboards, reports, billing records, configurations, and API credentials by tenant.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TEN-003
The system shall support tenant templates for onboarding common customer types such as SME, bank, telecom, utility, public-sector agency, healthcare provider, fintech, and MSSP customer.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TEN-004
The system shall support tenant status lifecycle: prospect, onboarding, active, suspended, churned, archived, and legally held.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TEN-005
The system shall support tenant-level package entitlement: asset limits, log volume limits, connectors, retention, SLA tier, included reports, playbook permissions, IR retainer hours, and AI features.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TEN-006
The system shall allow tenant admins to maintain organisation profile, contacts, escalation matrix, business hours, critical assets, legal/regulatory profile, and authority-to-act policy.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TEN-007
The system shall prevent cross-tenant data leakage through database design, API checks, search filters, reporting engine controls, cache scoping, and audit controls.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TEN-008
The system shall support customer-specific branding and white-labeling for authorised MSSP partners.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TEN-009
The system shall support tenant offboarding, export, retention freeze, archive, deletion workflow, legal hold, and certificate of destruction where permitted.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TEN-010
The system shall maintain a tenant change history for all material settings changes.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Tenant, Organisation and Account Management: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.

### 6.2 Identity, Access Management and Session Security
Req ID
Requirement
Priority
Phase
Acceptance Evidence
IAM-001
The system shall support local users, SSO through SAML/OIDC, MFA, API keys, service accounts, and temporary invitation links.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
IAM-002
The system shall implement role-based access control with optional attribute-based constraints for tenant, business unit, case sensitivity, data source, geography, and role duty.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
IAM-003
The system shall require MFA for internal platform users, SOC analysts, tenant admins, and any user with approval authority or export rights.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
IAM-004
The system shall support privileged access management workflows for platform super admins, including justification, time-bounded elevation, logging, and approval for high-risk actions.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
IAM-005
The system shall enforce least-privilege API scopes and token rotation for connector credentials.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
IAM-006
The system shall support break-glass access with emergency reason capture, automatic alerting, and post-use review.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
IAM-007
The system shall provide configurable session timeout, IP restrictions, device trust indicators, and geo-anomaly logging.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
IAM-008
The system shall provide user lifecycle events including invitation, activation, suspension, role change, password reset, MFA reset, and deactivation.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
IAM-009
The system shall provide access review reports for customer admins and internal compliance.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
IAM-010
The system shall log failed login attempts, MFA failures, suspicious admin behaviour, token usage, export access, and unusual session patterns.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Identity, Access Management and Session Security: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.

### 6.3 User Experience, Portals and Dashboards
Req ID
Requirement
Priority
Phase
Acceptance Evidence
UI-001
The system shall provide distinct but coherent experiences for customer users, SOC analysts, detection engineers, threat intelligence analysts, compliance users, platform admins, and MSSP partners.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
UI-002
The customer portal shall show incidents, risk posture, assets, integration health, open tasks, approvals, service metrics, reports, and evidence packs.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
UI-003
The analyst workbench shall show priority queues, alert context, entity graph, timeline, enrichment, runbook steps, AI assistance, notes, and escalation options.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
UI-004
The executive dashboard shall show risk trends, critical incidents, SLA compliance, exposure trends, control coverage, remediation progress, and business impact language.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
UI-005
The admin portal shall support tenant setup, entitlements, connector configuration, user roles, platform settings, feature flags, and billing.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
UI-006
The detection engineering workspace shall support rule authoring, testing, deployment, version history, tuning feedback, MITRE mapping, and coverage dashboards.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
UI-007
The compliance portal shall support audit requests, evidence packs, reporting templates, regulatory calendars, and control mappings.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
UI-008
The UI shall be responsive for tablet/laptop use and support dark mode for analyst SOC displays.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
UI-009
The UI shall include clear warning states for high-risk response actions and AI-generated recommendations.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
UI-010
The UI shall meet accessibility expectations for colour contrast, keyboard navigation, labels, and readable dashboards.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for User Experience, Portals and Dashboards: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.

### 6.4 Data Ingestion, Collection and Connector Framework
Req ID
Requirement
Priority
Phase
Acceptance Evidence
ING-001
The system shall ingest alerts, events, logs, assets, identities, vulnerabilities, tickets, threat intelligence, and customer metadata through connectors, syslog, webhooks, batch uploads, and APIs.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ING-002
The system shall provide a connector SDK with standard patterns for authentication, pagination, incremental polling, checkpointing, retry, error handling, normalization, and health metrics.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ING-003
The system shall support customer-side collectors for syslog, Windows event forwarding, cloud APIs, local file pickup, OT-adjacent feeds, and buffered offline operation.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ING-004
The system shall validate all inbound data against source schema and platform canonical schema, preserving raw original records in accordance with retention policy.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ING-005
The system shall detect ingestion gaps, connector failures, authentication failures, rate-limit issues, schema drift, duplicate payloads, and abnormal data volume changes.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ING-006
The system shall support backpressure and durable queues to prevent data loss under burst conditions.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ING-007
The system shall support tenant-specific routing and encryption from ingestion edge to storage.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ING-008
The system shall support source priority and classification so that critical data sources affect SLA and health dashboards.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ING-009
The system shall allow replay of historical data for testing new detections where retention permits.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ING-010
The system shall support ingestion quotas, overage tracking, package enforcement, and commercial alerts when customers exceed contracted volumes.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Data Ingestion, Collection and Connector Framework: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.


### 6.5 Normalization, Enrichment and Entity Resolution
Req ID
Requirement
Priority
Phase
Acceptance Evidence
NORM-001
The system shall normalize ingested data into a canonical event model inspired by OCSF-style categories, activities, observables, actors, assets, identities, network entities, cloud resources, and finding classes.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
NORM-002
The system shall preserve raw source fields for forensic traceability while exposing normalized fields for detection, search, correlation, dashboards, and reports.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
NORM-003
The system shall support parser versioning, regression tests, field mapping documentation, and schema drift alerts.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
NORM-004
The system shall enrich events with tenant context, asset criticality, user role, business unit, geo-location, threat intelligence, vulnerability exposure, and recent incident history.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
NORM-005
The system shall resolve entities across aliases, hostnames, IPs, MAC addresses, cloud instance IDs, user principal names, email addresses, device IDs, and external IDs.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
NORM-006
The system shall distinguish confidence levels in entity resolution and show analysts when relationships are inferred versus authoritative.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
NORM-007
The system shall support enrichment cache TTLs and prevent stale enrichment from misleading incident decisions.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
NORM-008
The system shall support customer-specific asset importance, crown-jewel tagging, and critical business-service mapping.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
NORM-009
The system shall support data quality dashboards showing unmapped fields, missing required fields, parser failure rates, and enrichment coverage.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
NORM-010
The system shall support privacy-preserving redaction or masking rules for sensitive fields by tenant and user role.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Normalization, Enrichment and Entity Resolution: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.

### 6.6 Detection Engineering and Rules Management
Req ID
Requirement
Priority
Phase
Acceptance Evidence
DET-001
The system shall provide a detection-as-code framework for rules, metadata, tests, dependencies, owners, version history, deployment workflow, and rollback.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
DET-002
The system shall support Sigma-like detection authoring and translation where applicable, plus native behavioral, threshold, sequence, correlation, and anomaly rules.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
DET-003
Every detection shall include title, description, severity, confidence, ATT&CK mapping, data source requirements, false-positive guidance, response playbook, owner, status, and test cases.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
DET-004
The system shall support global rules, industry pack rules, tenant-specific rules, beta rules, disabled rules, and emergency rules.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
DET-005
The system shall provide rule testing against sample data and historical tenant data where permitted.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
DET-006
The system shall support promotion flow: draft, peer review, QA test, pilot, production, tuned, deprecated, retired.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
DET-007
The system shall capture analyst feedback and false-positive dispositions to inform rule tuning.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
DET-008
The system shall provide MITRE ATT&CK coverage dashboards by tenant, package, sector, data source, and detection confidence.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
DET-009
The system shall detect and warn when a rule depends on a data source not active for a tenant.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
DET-010
The system shall support emergency deployment of high-priority detections with post-deployment review.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Detection Engineering and Rules Management: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.


### 6.7 Alert Correlation, Risk Scoring and Prioritisation
Req ID
Requirement
Priority
Phase
Acceptance Evidence
COR-001
The system shall deduplicate repeated alerts from the same source and correlate related alerts across endpoint, identity, email, network, cloud, vulnerability, and threat intelligence data.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COR-002
The system shall compute alert and incident risk scores using severity, confidence, asset criticality, user privilege, threat intel confidence, vulnerability exposure, business impact, recurrence, and kill-chain progression.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COR-003
The system shall support configurable correlation windows and tenant-specific correlation rules.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COR-004
The system shall group alerts into incidents where they share meaningful entities, sequence, campaign, threat actor, malware family, user account, host, domain, IP, or business process.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COR-005
The system shall identify escalation triggers such as privileged account involvement, crown-jewel asset, ransomware indicator, lateral movement, data exfiltration, persistence, or active exploitation.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COR-006
The system shall maintain explainability for risk scores by showing contributing factors and evidence.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COR-007
The system shall support suppression windows, maintenance windows, and approved-change context to reduce noise.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COR-008
The system shall identify alert storms and allow queue-level incident command mode.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COR-009
The system shall provide analyst-adjustable severity with mandatory reason capture.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COR-010
The system shall continuously measure correlation effectiveness and over-correlation risk.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Alert Correlation, Risk Scoring and Prioritisation: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.

### 6.8 Alert, Incident and Case Management
Req ID
Requirement
Priority
Phase
Acceptance Evidence
CASE-001
The system shall manage alert lifecycle: new, enriched, triaged, escalated, suppressed, converted to incident, duplicate, false positive, benign true positive, closed.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
CASE-002
The system shall manage incident lifecycle: opened, assigned, investigating, waiting customer, containment pending, contained, eradication, recovery, monitoring, closed, post-incident review.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
CASE-003
Every case shall include unique ID, tenant, title, severity, priority, category, affected entities, source alerts, timeline, owner, SLA, status, tasks, notes, evidence, communications, and audit trail.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
CASE-004
The system shall support internal-only and customer-visible notes, evidence, tasks, and status updates.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
CASE-005
The system shall support task assignment to analysts, customer users, external partners, or automated playbooks.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
CASE-006
The system shall support parent-child incidents, related incidents, duplicates, and major incident aggregation.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
CASE-007
The system shall provide templates for incident categories such as phishing, BEC, malware, ransomware, endpoint compromise, identity compromise, cloud compromise, data exfiltration, vulnerability exploitation, insider threat, DDoS, and policy violation.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
CASE-008
The system shall support attaching files, screenshots, log extracts, hashes, URLs, email headers, forensic artifacts, and chain-of-custody metadata.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
CASE-009
The system shall enforce closure criteria including disposition, root cause, impact, actions taken, lessons learned, and customer acknowledgement where required.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
CASE-010
The system shall provide searchable case history and knowledge-base linking.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Alert, Incident and Case Management: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.

### 6.9 Investigation Workbench, Timeline and Entity Graph
Req ID
Requirement
Priority
Phase
Acceptance Evidence
INV-001
The system shall provide a unified investigation view with correlated alerts, raw events, entity profile, enrichment, timeline, runbook, notes, tasks, and AI summary.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
INV-002
The timeline shall show event time, ingest time, source, entity, action, severity, confidence, analyst actions, automation actions, customer communications, and evidence capture.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
INV-003
The entity graph shall show relationships among users, devices, IPs, domains, files, processes, emails, cloud resources, vulnerabilities, tickets, and incidents.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
INV-004
The system shall allow analysts to pivot from an entity to related events, incidents, vulnerabilities, alerts, and historical activity.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
INV-005
The system shall support investigation notebooks with structured sections for hypothesis, evidence, analysis, decision, and next action.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
INV-006
The system shall support query builder and advanced search across normalized fields and raw data, subject to user permissions and retention.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
INV-007
The system shall preserve every query, export, and evidence selection in the audit log for sensitive cases.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
INV-008
The system shall support saved investigation views and shareable internal links.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
INV-009
The system shall show missing context and data-source gaps to prevent false confidence.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
INV-010
The system shall support war-room mode for major incidents with live timeline updates and assigned roles.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Investigation Workbench, Timeline and Entity Graph: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.

### 6.10 Threat Intelligence Management
Req ID
Requirement
Priority
Phase
Acceptance Evidence
TI-001
The system shall ingest threat intelligence through STIX/TAXII, MISP-like feeds, CSV/API imports, commercial feeds, internal advisories, and manual analyst submissions.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TI-002
The system shall support intelligence objects including indicators, malware, campaigns, threat actors, attack patterns, tools, vulnerabilities, reports, and sightings.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TI-003
The system shall track confidence, source reliability, first seen, last seen, TLP classification, expiry, kill-chain phase, ATT&CK mapping, and permitted sharing scope.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TI-004
The system shall enrich alerts and incidents with relevant intelligence and show why a match matters.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TI-005
The system shall prevent blind blocking on low-confidence indicators without analyst or policy review.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TI-006
The system shall support converting intelligence into detection rules, watchlists, hunting queries, customer advisories, and evidence-pack references.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TI-007
The system shall support sector-specific intelligence packs and country/regional intelligence packs.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TI-008
The system shall support indicator decay, expiry, revocation, and suppression to reduce stale intelligence risk.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TI-009
The system shall support internal intelligence reporting and customer-facing advisories with TLP labels.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
TI-010
The system shall support intelligence sharing communities where legally and contractually permitted.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Threat Intelligence Management: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.

### 6.11 SOAR, Playbooks and Response Automation
Req ID
Requirement
Priority
Phase
Acceptance Evidence
SOAR-001
The system shall provide a playbook engine with trigger, condition, enrichment, decision, approval, action, notification, wait, branch, rollback-guidance, and closure steps.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
SOAR-002
The system shall provide a controlled action catalog including notify, ticket, enrich, block IP/domain/hash, quarantine email, disable user, revoke session, isolate endpoint, collect evidence, request customer action, and generate report.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
SOAR-003
The system shall enforce authority-to-act rules per tenant, package, data source, action type, severity, business hours, and approval group.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
SOAR-004
The system shall classify actions as informational, low impact, medium impact, high impact, and business critical.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
SOAR-005
The system shall require human approval for high-impact actions unless contractually pre-authorised and technically safe.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
SOAR-006
The system shall log every playbook execution, input, output, decision, approval, error, retry, and action result.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
SOAR-007
The system shall support dry-run/simulation mode for playbook testing.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
SOAR-008
The system shall support playbook versioning, review, approval, rollback, and tenant-specific overrides.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
SOAR-009
The system shall support playbook failure handling, partial execution recovery, and escalation to human analysts.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
SOAR-010
The system shall support business continuity mode where automation is reduced during known integration instability.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for SOAR, Playbooks and Response Automation: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.


### 6.12 AI SOC Copilot and Agentic Investigation
Req ID
Requirement
Priority
Phase
Acceptance Evidence
AI-001
The system shall provide AI assistance for triage summaries, incident narratives, evidence extraction, timeline explanation, probable root cause, recommended next steps, and report drafts.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
AI-002
AI outputs shall be grounded in retrieved platform evidence and cite the underlying alerts, events, entities, case notes, and playbook steps used.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
AI-003
AI shall distinguish facts, inferences, assumptions, and recommended actions.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
AI-004
AI shall not execute containment or destructive actions directly; it may recommend or prepare actions for approved playbooks subject to authority-to-act controls.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
AI-005
The system shall log prompts, context packages, model outputs, user edits, approvals, rejections, and feedback for audit and model evaluation.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
AI-006
The system shall prevent tenant data from being used to train public models unless explicitly contracted and technically controlled.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
AI-007
The system shall support model selection by deployment model, including private model, hosted model, customer-managed model, or no-AI mode.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
AI-008
The system shall support AI safety tests for hallucination, unsafe recommendation, cross-tenant leakage, prompt injection, and unsupported claims.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
AI-009
The system shall support redaction and minimisation of sensitive fields before sending data to external AI services where allowed.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
AI-010
The system shall present AI assistance as decision support, not a final authority.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for AI SOC Copilot and Agentic Investigation: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.


### 6.13 Reporting, Dashboards and Evidence Packs
Req ID
Requirement
Priority
Phase
Acceptance Evidence
REP-001
The system shall generate operational, customer, executive, board, audit, regulatory, service review, and post-incident reports.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
REP-002
The reporting engine shall support templates, scheduled delivery, ad hoc export, filtering, watermarking, approval, and distribution lists.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
REP-003
Reports shall include clear data-period, tenant, scope, data-source coverage, limitations, definitions, and evidence references.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
REP-004
The system shall generate monthly service review packs including incidents, SLA performance, false-positive rate, top risks, integrations health, actions taken, recommendations, and open remediation tasks.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
REP-005
The system shall generate executive cyber posture summaries in business language.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
REP-006
The system shall generate regulatory evidence packs aligned to configured frameworks and jurisdiction-specific templates.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
REP-007
The system shall provide export formats including PDF, DOCX, XLSX/CSV, JSON, and API where appropriate.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
REP-008
The system shall audit every report generation, export, and download.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
REP-009
The system shall prevent users from exporting data outside their permissions or tenant scope.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
REP-010
The system shall support white-label reporting for MSSP partners.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Reporting, Dashboards and Evidence Packs: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.

### 6.14 Compliance, Control Mapping and Regulatory Evidence
Req ID
Requirement
Priority
Phase
Acceptance Evidence
COMP-001
The system shall map detections, incidents, evidence, response actions, assets, vulnerabilities, and reports to configurable control frameworks.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMP-002
The system shall provide framework templates for NIST CSF, CIS Controls, ISO 27001-style control domains, data protection, critical infrastructure, and customer-specific regulatory obligations.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMP-003
The system shall support Ghana sovereign SOC and similar country-specific packs as configurable market packages rather than hardcoded product logic.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMP-004
The system shall support evidence requests, evidence owner assignment, due dates, status tracking, and exportable evidence bundles.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMP-005
The system shall maintain chain-of-custody metadata for incident evidence and forensic artifacts.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMP-006
The system shall support regulatory incident notification preparation, including timeline, affected systems, known impact, actions taken, and next steps.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMP-007
The system shall support policy acknowledgement and customer shared-responsibility documentation.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMP-008
The system shall support audit-readiness dashboards showing control coverage and evidence freshness.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMP-009
The system shall support retention and deletion rules by jurisdiction, contract, tenant, and data class.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMP-010
The system shall support compliance exceptions and risk acceptance records.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Compliance, Control Mapping and Regulatory Evidence: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.


### 6.15 Asset, Identity, Vulnerability and Exposure Management
Req ID
Requirement
Priority
Phase
Acceptance Evidence
ASSET-001
The system shall maintain an asset inventory from connectors, manual uploads, agent/collector feeds, cloud inventories, vulnerability tools, and customer APIs.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ASSET-002
Assets shall include type, owner, business unit, criticality, location, environment, operating system, cloud account, exposure status, tags, vulnerabilities, and related incidents.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ASSET-003
The system shall maintain identity inventory including users, service accounts, privileged accounts, groups, roles, status, MFA state where available, and risky sign-in context.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ASSET-004
The system shall ingest vulnerabilities and map them to assets, criticality, exploitability, active exploitation intelligence, and open remediation tasks.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ASSET-005
The system shall support crown-jewel asset tagging and business service mapping.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ASSET-006
The system shall support attack surface and exposure dashboards for managed vulnerability add-on services.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ASSET-007
The system shall correlate alerts with exposed vulnerabilities and privileged identities to increase priority.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ASSET-008
The system shall support exceptions, accepted risk, compensating controls, and remediation target dates.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ASSET-009
The system shall support asset confidence scoring when data comes from multiple conflicting sources.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ASSET-010
The system shall support customer tasks for missing owner, missing criticality, stale asset, and unresolved vulnerability context.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Asset, Identity, Vulnerability and Exposure Management: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.

### 6.16 Notification, Communication and Collaboration
Req ID
Requirement
Priority
Phase
Acceptance Evidence
COMM-001
The system shall support email, Teams, Slack, SMS/WhatsApp gateway integration where permitted, in-platform notifications, API callbacks, and ITSM ticket comments.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMM-002
The system shall route communications according to tenant escalation matrix, severity, business hours, package SLA, and incident type.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMM-003
The system shall support customer approval requests for response actions with clear risk, evidence, recommended action, expiry, and fallback path.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMM-004
The system shall support internal analyst shift handover notes and major incident war-room channels.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMM-005
The system shall maintain immutable communication logs for incident cases.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMM-006
The system shall support notification throttling, digest mode, and escalation if no acknowledgement is received.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMM-007
The system shall support different communication templates for technical users, executives, regulators, and auditors.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMM-008
The system shall support bilingual/localized templates for country deployments where required.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMM-009
The system shall support secure links with expiry for sensitive reports and approval actions.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
COMM-010
The system shall prevent sensitive incident details from being sent to insecure channels unless explicitly allowed by policy.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Notification, Communication and Collaboration: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.

### 6.17 Packages, Entitlements, Billing and Commercial Controls
Req ID
Requirement
Priority
Phase
Acceptance Evidence
BILL-001
The system shall define commercial packages with included assets, users, connectors, log volume, retention, SLA, reports, AI features, playbooks, and analyst entitlements.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
BILL-002
The system shall meter log volume, alert volume, storage, connector count, asset count, report count, API usage, playbook actions, and professional service hours.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
BILL-003
The system shall support overage alerts, contract thresholds, billing export, and finance review workflows.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
BILL-004
The system shall support add-on services including incident response, digital forensics, vulnerability scanning, tabletop exercises, compliance evidence packs, threat hunting, and custom integrations.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
BILL-005
The system shall prevent silent scope creep by requiring commercial approval for unsupported custom work.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
BILL-006
The system shall support customer renewal status, contract dates, payment terms, service suspension, and downgrade/upgrade workflows.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
BILL-007
The system shall support partner/reseller pricing and downstream tenant billing metadata.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
BILL-008
The system shall support margin dashboards by package, customer, connector, storage volume, analyst time, and add-on service.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
BILL-009
The system shall support onboarding fees, mobilisation fees, minimum annual commitments, and framework/anchor customer pricing rules.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
BILL-010
The system shall integrate with external finance systems in later phases.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Packages, Entitlements, Billing and Commercial Controls: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.


### 6.18 Platform Administration, Configuration and Feature Flags
Req ID
Requirement
Priority
Phase
Acceptance Evidence
ADMIN-001
The system shall provide global configuration for packages, connectors, rule packs, report templates, retention policies, AI providers, action catalog, and deployment settings.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ADMIN-002
The system shall support feature flags by environment, tenant, package, partner, region, and beta programme.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ADMIN-003
The system shall provide platform health dashboards for queues, storage, API latency, connector health, job failures, AI service health, and report generation status.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ADMIN-004
The system shall support configuration audit logs and rollback for material settings.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ADMIN-005
The system shall provide admin workflows for tenant creation, migration, suspension, export, legal hold, and deletion.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ADMIN-006
The system shall provide data repair and reprocessing tools with strict permissions and audit logs.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ADMIN-007
The system shall support content library management for detections, playbooks, report templates, compliance mappings, and knowledge base articles.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ADMIN-008
The system shall support maintenance windows, incident banners, release notes, and customer-visible platform status.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ADMIN-009
The system shall support secrets rotation reminders and connector credential expiry tracking.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test
ADMIN-010
The system shall support support-ticket and customer support workflows for platform issues.
Must
MVP/V1 depending on dependency
Functional test + role/tenant security test

Implementation note for Platform Administration, Configuration and Feature Flags: the build team shall convert each requirement above into user stories, API contracts, database migrations, UI screens, validation tests, permission tests, and operational test scripts. Cybersecurity subject matter experts shall review security-sensitive workflows before production release.


## 7. Data, Schema, Storage and Retention Requirements

### 7.1 Canonical Data Domains
Data Entity
Description
Tenant
Organisation/customer partition with package, settings, contacts, policies, compliance profile, and deployment metadata.
User
Platform user or customer user with identity, roles, permissions, MFA status, tenant association, and audit history.
Role/Permission
Access-control configuration including RBAC/ABAC constraints, action permissions, export rights, and approval authority.
Integration
Configured connector with credentials, scopes, status, health, data types, polling settings, and source metadata.
Collector
Customer-side or platform-side data collection service with version, host, route, buffer status, and health.
Raw Event
Original event/log/alert/finding payload preserved in source format subject to retention and privacy policy.
Normalized Event
Canonical representation of a source event with mapped fields, metadata, confidence, and entity references.
Alert
Actionable security signal generated by source tool, detection rule, correlation rule, AI-assisted review, or manual submission.
Incident/Case
Investigation container with alerts, timeline, entities, tasks, evidence, notes, communications, SLAs, and closure data.
Entity
User, host, IP, domain, URL, file, process, cloud resource, email, account, vulnerability, or business service involved in events.
Asset
Device, server, workload, cloud resource, application, OT/IoT system, network device, or business system under monitoring.
Vulnerability
Weakness or exposure mapped to assets, severity, exploitability, remediation state, and related incidents.
Detection Rule
Versioned logic, metadata, test cases, status, mapping, and tuning information.
Playbook
Versioned workflow with trigger, conditions, steps, approvals, actions, and execution logs.
Threat Intelligence Object
Indicator, campaign, actor, tool, malware, attack pattern, report, sighting, or intelligence note.
Evidence Item
Artifact attached to case/report with source, hash, chain-of-custody, classification, and retention.
Report
Generated document/dashboard export with scope, template, recipients, approvals, and access history.
Audit Log
Immutable record of user, system, API, AI, automation, admin, export, and data-access events.
Billing Usage Record
Metered record of assets, logs, connectors, storage, reports, playbook actions, AI usage, and service hours.
Compliance Evidence Record
Control-mapped evidence, owner, status, expiry, exception, risk acceptance, and export history.


### 7.2 Canonical Event Field Requirements
Field
Requirement
event_id
Unique platform event ID.
tenant_id
Tenant partition ID; mandatory for every record.
source_system
Connector/source tool name and instance.
source_event_id
Original source event ID if available.
event_time
Time event occurred at source.
ingest_time
Time platform received event.
event_category
Normalized category such as identity, endpoint, network, email, cloud, vulnerability, threat intel, system.
event_activity
Normalized activity/action.
severity
Source severity and normalized severity.
confidence
Confidence in detection or enrichment.
actor
User, process, service, or external actor.
target
Affected resource, user, file, or asset.
src_ip
Source IP.
dst_ip
Destination IP.
domain
Domain/hostname if applicable.
url
URL if applicable.
file_hash
Hash fields for file observables.
process
Process name/path/cmdline if applicable.
cloud_account
Cloud tenant/account/subscription/project.
asset_id
Resolved platform asset ID.
identity_id
Resolved identity ID.
raw_ref
Pointer to raw event payload.
parser_version
Parser version used.
data_classification
Classification of event fields and masking rules.
mitre_tags
Mapped ATT&CK tactics/techniques where available.
case_refs
Related alert/incident IDs.
enrichment_refs
Threat intel, vulnerability, geo, reputation references.


### 7.3 Storage Classes
Storage Class
Purpose
Default Retention
Notes
Hot event store
Fast search, detection, investigation, recent dashboards.
30-90 days by package.
Higher tiers may include longer hot retention.
Warm analytics store
Historical analytics, trend reporting, rule testing.
90-365 days by package.
May use cheaper query-optimised storage.
Archive/object storage
Long-term evidence, raw events, reports.
1-7 years by contract/regulation.
Encrypted, access-controlled, legal-hold capable.
Relational case DB
Tenants, users, cases, tasks, configs, reports, billing.
Life of contract plus retention policy.
Strong integrity, backups, audit logs.
Vector/knowledge store
Knowledge base, AI retrieval, detection context.
According to data classification.
Must enforce tenant separation.
Immutable audit store
Security-relevant audit events.
Minimum 1 year; longer for regulated tiers.
Tamper-evident controls required.


### 7.4 Retention and Deletion Requirements
Req ID
Requirement
DATA-001
The system shall support retention policies by tenant, data class, package, jurisdiction, and legal hold status.
DATA-002
The system shall support deletion workflows for tenant offboarding while preserving audit/legal records where contractually or legally required.
DATA-003
The system shall prevent deletion of evidence under active legal hold or active major incident review.
DATA-004
The system shall provide retention preview showing what will be deleted/archived before policy execution.
DATA-005
The system shall log retention policy execution and deletion outcomes.
DATA-006
The system shall support customer export before deletion where contractually allowed.
DATA-007
The system shall support data minimisation and field-level masking for sensitive personal data.
DATA-008
The system shall support customer-specific encryption keys or key namespaces for dedicated/regulated tiers.
DATA-009
The system shall provide data residency metadata and prevent routing data to prohibited regions.
DATA-010
The system shall support disaster recovery restoration without violating tenant isolation or retention policies.



## 8. Integration and Connector Requirements

### 8.1 Integration Strategy
The platform shall be integration-first but not integration-dependent. Native case management, alert queue, reporting, AI triage, evidence handling, packages, and SOC workflows must operate with basic syslog, webhook, API, and manual uploads. Vendor-specific connectors increase depth and automation but must be implemented in phases based on market value, customer demand, and technical feasibility.

### 8.2 Connector Priority Roadmap
Phase
Connector
Target Use
Purpose
P0
Generic API/Webhook Ingest
All customers
Inbound alerts/events/findings/assets; flexible early integration.
P0
Syslog Collector
Firewalls, network devices, Linux, appliances
Broadest generic log source coverage.
P0
Email Notifications
All customers
Customer escalations and service communication.
P1
Microsoft 365
Most enterprises/SMEs
Email, audit, identity, collaboration security context.
P1
Microsoft Entra ID
Identity-first detection
Sign-ins, risky users, groups, privileged identity context; disable/revoke actions.
P1
Microsoft Defender for Endpoint
Endpoint MDR
Endpoint alerts, device isolation, investigation packages.
P1
Teams
Customer approvals and notifications
Collaboration and major incident war-room support.
P1
Jira/ServiceNow
Enterprise service management
Ticket sync and remediation task management.
P2
AWS
Cloud security
CloudTrail, GuardDuty, IAM, EC2, S3 events, response tasks.
P2
Azure
Cloud security
Activity logs, Defender for Cloud, resource inventory.
P2
Google Workspace
Identity/email collaboration
Audit logs and identity/email signals.
P2
Fortinet
Network security
Firewall alerts, syslog, block actions.
P2
Palo Alto
Network/security platform
Firewall, Prisma, Cortex integration potential.
P2
CrowdStrike
Endpoint/XDR
Falcon detections, host context, containment actions.
P2
SentinelOne
Endpoint/XDR
Endpoint detections and response actions.
P2
Sophos
Endpoint/email/network
Endpoint alerts and security context.
P3
Cisco
Network/security
Umbrella, Secure Endpoint, Meraki, firewall/network signals.
P3
Okta
Identity
Identity logs, risk, user/session response.
P3
Cloudflare
Edge/SASE/DNS
DNS, WAF, Zero Trust, blocked traffic.
P3
Zscaler
SASE/SWG
Web access and private access telemetry.
P3
GCP
Cloud security
Cloud audit logs, SCC findings, IAM context.
P3
Vulnerability Scanners
Exposure management
Tenable, Qualys, Rapid7, Defender VM.
P3
Email Security Platforms
Phishing/BEC
Proofpoint, Mimecast, Defender, Barracuda or similar.
P4
Customer Sector APIs
Banks, telecoms, utilities, public sector
Sector-specific telemetry and compliance workflows.


### 8.3 Standard Connector Requirements
Req ID
Requirement
CONN-001
Every connector shall declare supported data types, auth method, required scopes, polling method, rate limits, retries, pagination, checkpointing, and schema version.
CONN-002
Every connector shall expose health status, last successful run, error count, data volume, event lag, credential expiry, and parser failure rate.
CONN-003
Every connector shall support tenant-scoped credentials and never reuse credentials across tenants.
CONN-004
Every connector shall encrypt stored secrets and restrict secret access to the connector runtime.
CONN-005
Every connector shall support test connection, permissions validation, and guided setup instructions.
CONN-006
Every connector shall support idempotent ingestion and duplicate handling.
CONN-007
Every connector shall record raw payload references, normalized payload status, and mapping version.
CONN-008
Outbound response connectors shall validate authority-to-act before executing actions.
CONN-009
Outbound actions shall capture external action IDs and final status.
CONN-010
Connectors shall fail safely and escalate to analysts if response action status is unknown.


### 8.4 Connector Contract Template
Contract Element
Required Content
Connector Name
Vendor/product/source and version.
Connector Type
Inbound alert, inbound log, asset inventory, vulnerability, identity, outbound action, ticketing, messaging, threat intelligence.
Authentication
OAuth, API key, certificate, service account, webhook secret, SAML/OIDC, or syslog TLS.
Permissions
Minimum required permissions and optional permissions for response actions.
Data Objects
Alerts, users, endpoints, vulnerabilities, cloud resources, emails, network flows, events, tickets, indicators.
Polling/Streaming
Polling interval, webhook endpoint, syslog listener, batch schedule, backfill support.
Rate Limits
Vendor rate limits and retry/backoff approach.
Normalization Mapping
Canonical fields, parser version, unmapped field handling.
Health Metrics
Last event time, last success, errors, data volume, lag, expiry.
Security
Secret storage, tenant isolation, TLS, IP allowlisting, credential rotation.
Testing
Unit tests, sandbox tests, tenant setup tests, action simulation tests.
Documentation
Customer setup guide, troubleshooting, permissions risk, known limitations.



## 9. AI SOC, Detection Engineering and SOAR Requirements

### 9.1 AI Principles
AI is a copilot and workflow accelerator, not an uncontrolled decision-maker.
AI outputs must be grounded in platform evidence and distinguish fact from inference.
AI shall be prevented from cross-tenant leakage by architecture, retrieval scoping, prompt construction, access controls, and logging.
AI shall never be the sole approver of high-impact containment actions.
AI recommendations must be reviewable, editable, rejectable, and measurable.
AI shall support no-AI mode, private-model mode, hosted-model mode, and customer-specific restrictions where commercially required.

### 9.2 AI Feature Requirements
ID
Feature
Requirement
AI-F-001
Alert summarisation
Generate concise summary of what triggered, affected entity, why it matters, and suggested triage steps.
AI-F-002
Incident narrative
Create an incident story with timeline, likely sequence, affected systems, evidence and remaining unknowns.
AI-F-003
Evidence extraction
Identify key observables, suspicious actions, relevant logs, and missing data for analyst review.
AI-F-004
MITRE mapping assistance
Suggest likely ATT&CK tactics/techniques based on evidence with confidence and rationale.
AI-F-005
Recommended next action
Suggest safe next investigation or response steps based on playbook and authority-to-act.
AI-F-006
Customer update draft
Draft customer-facing technical and executive updates for analyst approval.
AI-F-007
Post-incident report draft
Draft PIR including root cause, impact, response timeline, lessons learned, and recommendations.
AI-F-008
Detection tuning assistant
Summarise false-positive patterns and recommend rule tuning for detection engineer review.
AI-F-009
Threat intel explainer
Explain indicator/campaign relevance in analyst-friendly language.
AI-F-010
Query assistant
Generate search queries from natural language, subject to preview and analyst execution.
AI-F-011
Playbook assistant
Recommend playbook branch or next step, not direct high-risk action execution.
AI-F-012
Executive summary
Create board-ready monthly cyber posture summary using service metrics and incident context.


### 9.3 AI Control Requirements
Req ID
Requirement
AI-C-001
AI retrieval shall be tenant-scoped and permission-filtered.
AI-C-002
AI context packages shall include only necessary evidence and be logged.
AI-C-003
AI responses shall cite source records or state when confidence is low.
AI-C-004
AI shall not invent evidence, dates, indicators, or actions.
AI-C-005
AI-generated customer communications shall require human approval before external delivery.
AI-C-006
AI-generated response actions shall require playbook approval workflow.
AI-C-007
The system shall test AI features for prompt injection using malicious log/event content.
AI-C-008
The system shall provide model/provider configuration and data routing restrictions by tenant.
AI-C-009
The system shall maintain feedback labels: useful, incorrect, unsafe, hallucinated, insufficient evidence, accepted, edited.
AI-C-010
The system shall periodically evaluate AI outputs against analyst-reviewed ground truth.


### 9.4 Detection Lifecycle
Stage
Required Controls
Outputs
Intake
Threat intel, customer request, incident lesson learned, coverage gap, regulatory need.
Detection request ticket.
Design
Define logic, data sources, fields, severity, false positives, ATT&CK mapping, playbook.
Detection design record.
Author
Create Sigma/native rule and tests.
Rule draft and test data.
Peer Review
Detection engineer and SOC analyst review for logic and operational value.
Review approval/rework.
Test
Run against sample and historical data where allowed.
Test results and expected alert examples.
Pilot
Deploy to limited tenant/group or shadow mode.
Pilot findings and FP rate.
Production
Deploy with monitoring and rollback plan.
Active rule version.
Tune
Adjust thresholds, exclusions, context, severity.
Tuning record.
Retire
Remove obsolete noisy/unsafe rules.
Retirement reason and replacement mapping.


### 9.5 SOAR Action Risk Classes
Class
Examples
Approval Requirement
Class 0 - Informational
Enrich indicator, retrieve asset profile, create internal note.
No approval; system logged.
Class 1 - Low Impact
Create ticket, notify internal analyst, add watchlist item.
Policy-based approval optional.
Class 2 - Medium Impact
Customer notification, request password reset, mark email for review.
Analyst approval required unless package pre-authorises.
Class 3 - High Impact
Disable user, revoke sessions, isolate endpoint, block business domain/IP.
Customer or authorised senior approval required unless explicit pre-authorised containment.
Class 4 - Business Critical
Network-wide block, mass quarantine, cloud account lockdown, production service disruption.
Incident commander + customer authority required; no full autonomous execution in MVP/V1.



## 10. Incident Response, SOC Operations and Service Management Requirements

### 10.1 SOC Tiers and Responsibilities
Role
Responsibilities
Platform Needs
Tier 1 Analyst
Queue monitoring, initial triage, enrichment review, false-positive closure, escalation, customer notification drafts.
Fast queues, playbooks, AI summary, closure templates, SLA timers.
Tier 2 Analyst
Deep investigation, timeline building, containment recommendations, customer technical coordination.
Entity graph, advanced search, notebooks, response approval, evidence handling.
Tier 3 / IR Lead
Major incidents, threat hunting, response strategy, forensic readiness, PIR leadership.
War room, chain-of-custody, advanced queries, high-risk actions, PIR templates.
Detection Engineer
Rule creation/tuning, coverage, test lab, content QA.
Detection workspace, rule tests, FP feedback, coverage dashboard.
SOC Manager
Shift control, QA, queue health, analyst performance, service review.
Ops dashboard, utilisation, QA sampling, escalation metrics.
Customer Success Manager
Onboarding, service reviews, customer satisfaction, renewal risk.
Customer health, reports, open tasks, contract entitlements.
Compliance Manager
Evidence packs, audit response, regulatory mapping.
Control mapping, evidence workflows, export approvals.


### 10.2 Severity Model
Severity
Definition
Examples
Response Expectations
P1 Critical
Confirmed or highly likely active compromise causing or likely to cause material business impact.
Ransomware activity, privileged account takeover, active exfiltration, crown-jewel compromise.
Immediate triage, senior escalation, customer emergency notification, war-room mode.
P2 High
Credible threat requiring urgent investigation and potential containment.
Malware on critical host, impossible travel privileged login, EDR high confidence detection.
Priority queue, Tier 2 escalation, customer notification per SLA.
P3 Medium
Suspicious activity requiring investigation but no immediate material impact evident.
Phishing clicked, unusual sign-in, suspicious PowerShell, exposed vulnerable asset.
Standard triage and customer task as needed.
P4 Low
Low confidence or policy/security hygiene finding.
Blocked commodity malware, failed brute-force attempts, benign policy alert.
Triage, tune/suppress if noisy, monthly reporting if applicable.
P5 Informational
Awareness, health, or advisory item.
Connector health, threat advisory, control observation.
Notification/reporting only.


### 10.3 Minimum SOC Process Requirements
Req ID
Requirement
OPS-001
Every shift shall start with queue review, major incident review, open customer approval review, integration health review, and handover notes.
OPS-002
Every P1/P2 incident shall have named incident owner, severity rationale, affected entities, next action, and customer communication status.
OPS-003
Every incident shall maintain a timeline of system events, analyst actions, customer actions, AI assistance, and playbook actions.
OPS-004
Every closure shall include disposition, root cause if known, impact, actions taken, customer tasks, and detection feedback.
OPS-005
Every false positive shall capture reason category and rule/data-source feedback.
OPS-006
Every major incident shall produce a post-incident report and lessons-learned action list.
OPS-007
Every customer shall have onboarding baseline, escalation matrix, critical asset list, and authority-to-act settings before production monitoring.
OPS-008
Every month, each managed customer shall receive a service report unless package excludes it.
OPS-009
SOC management shall sample and QA closed cases for quality and consistency.
OPS-010
The platform shall support audit of analyst workload, queue ageing, SLA breaches, and customer waiting states.


### 10.4 Core Playbook Catalogue
ID
Playbook
Required Content
PB-001
Phishing / Suspicious Email
Email headers, URL reputation, sender domain, user clicked, attachment hash, mailbox search, quarantine request, user guidance.
PB-002
Business Email Compromise
Mailbox rules, sign-in anomalies, MFA status, forwarding rules, OAuth consent, financial system exposure, urgent containment.
PB-003
Ransomware Indicators
EDR alerts, mass file changes, suspicious encryption tools, lateral movement, isolate endpoint, backup/service impact checks.
PB-004
Endpoint Malware
EDR detection, hash/process tree, host isolation, scan, user context, related hosts, closure after clean state.
PB-005
Privileged Account Compromise
Risky sign-in, impossible travel, privilege change, session revocation, password reset, PAM review.
PB-006
Cloud IAM Abuse
New access keys, privilege escalation, unusual API calls, cloud trail review, key disablement approval.
PB-007
Data Exfiltration
Large outbound transfer, unusual destination, DLP alerts, affected data class, containment and legal/privacy escalation.
PB-008
Vulnerability Exploitation
Exploit intel, vulnerable assets, WAF/firewall events, patch/workaround tasks, customer risk acceptance.
PB-009
Firewall / Network Intrusion
IDS/IPS events, blocked/allowed flow, asset criticality, threat intel, block rule request.
PB-010
Suspicious PowerShell / Script Execution
Command line, parent process, user context, host criticality, known admin tools vs attacker tradecraft.
PB-011
New Persistence Mechanism
Scheduled task, service creation, startup folder, registry run key, cloud persistence, containment plan.
PB-012
DDoS / Service Availability
Traffic anomaly, provider telemetry, customer business impact, mitigation provider escalation.
PB-013
Insider Risk Indicator
Unusual access, data movement, privileged action, HR/legal handling, confidentiality controls.
PB-014
Third-Party/Supply Chain Alert
Vendor compromise advisory, exposed integration, indicators, affected customers, notification and mitigation.
PB-015
Connector Health Failure
Critical data-source outage, customer alert, remediation task, SLA impact, compensating monitoring.



## 11. Compliance, Regulatory Evidence and Governance Requirements

### 11.1 Compliance Product Design
Compliance shall be implemented as configurable mappings and evidence workflows rather than hardcoded country-specific logic. Country-specific packs such as Ghana sovereign SOC, Nigerian regulated enterprise, UK financial services, EU-style data protection, or public-sector CII shall be deployable as templates containing control mappings, reporting calendars, evidence expectations, report templates, and data-residency rules.

### 11.2 Governance Requirements
Req ID
Requirement
GOV-001
The platform shall maintain an immutable audit trail for all administrative, analyst, API, automation, AI, export, and security-sensitive actions.
GOV-002
The platform shall support internal governance dashboards for risk, audit findings, control exceptions, data retention, access review, and operational incidents.
GOV-003
The platform shall support customer-facing assurance reports summarising security controls, availability, incident handling process, and evidence handling.
GOV-004
The platform shall support mapping of service obligations to customer contracts and packages.
GOV-005
The platform shall support documented shared responsibility model per deployment/package.
GOV-006
The platform shall track policy acknowledgements by customers and internal users.
GOV-007
The platform shall support exportable evidence for external audits and regulatory reviews.
GOV-008
The platform shall support escalation and reporting workflows for suspected data breach, security incident, service outage, or SLA breach.
GOV-009
The platform shall support separation of duties for rule deployment, privileged admin, billing override, data export, and high-risk response actions.
GOV-010
The platform shall support regular access review and certification.


### 11.3 Evidence Pack Requirements
Evidence Pack Type
Included Evidence
Monthly Service Review
Open/closed incidents, SLA performance, integration health, false positives, top recurring detections, recommendations, open customer tasks.
Board Cyber Posture
Risk trends, major incidents, attack themes, control gaps, exposure summary, business impact, management actions.
Regulatory/CII Evidence
Monitoring coverage, incident handling timeline, data-source health, response actions, escalation logs, control mapping.
Post-Incident Report
Executive summary, technical timeline, affected assets/users, root cause, impact, containment/eradication/recovery actions, lessons learned.
Audit Evidence Bundle
Access logs, detection records, incident samples, evidence chain, reports, approvals, playbook execution logs.
Customer Onboarding Evidence
Scope, contacts, assets, authority-to-act, connectors, baseline tuning, test alerts, go-live sign-off.



## 12. Non-Functional Requirements
Availability and Resilience
Req ID
Requirement
NFR-AV-001
The system shall be designed for high availability with redundant critical services and graceful degradation.
NFR-AV-002
The system shall define SLOs for API availability, ingestion availability, alert processing, report generation, and UI access.
NFR-AV-003
The system shall provide disaster recovery with defined RPO/RTO per deployment tier.
NFR-AV-004
The system shall support queue buffering during downstream outages.
NFR-AV-005
The system shall provide customer-visible status for integration and platform outages.

Performance and Scalability
Req ID
Requirement
NFR-PERF-001
The system shall process high-volume event streams with horizontal scaling of ingestion, parsing, detection, enrichment, and storage.
NFR-PERF-002
The analyst UI shall load priority queues within acceptable interactive response times under normal load.
NFR-PERF-003
Search shall support time-bounded queries over hot data with predictable performance.
NFR-PERF-004
Report generation shall be asynchronous for large reports.
NFR-PERF-005
The platform shall support capacity forecasting and usage trends by tenant.

Security
Req ID
Requirement
NFR-SEC-001
The platform shall be secure-by-design with threat modelling for major features.
NFR-SEC-002
All network communications shall use strong TLS.
NFR-SEC-003
Data at rest shall be encrypted using managed keys or customer/dedicated keys where applicable.
NFR-SEC-004
Secrets shall be stored in a secrets manager and never in code or logs.
NFR-SEC-005
The platform shall support regular vulnerability scanning, dependency scanning, SAST, DAST, IaC scanning, and penetration testing.
NFR-SEC-006
The platform itself shall be monitored by its own security controls and alerting.
NFR-SEC-007
Production access shall be controlled through least privilege, MFA, logging, and approval for privileged actions.
NFR-SEC-008
Every data export shall be permission checked and logged.
NFR-SEC-009
The system shall prevent cross-tenant leakage at application, database, cache, search, object store, report, AI, and logging layers.
NFR-SEC-010
The system shall provide tamper-evident audit logging for sensitive actions.

Privacy and Data Protection
Req ID
Requirement
NFR-PRI-001
The platform shall support data minimisation, masking, pseudonymisation, retention, deletion, export, and legal hold policies.
NFR-PRI-002
The platform shall classify sensitive personal data and restrict access by role.
NFR-PRI-003
The platform shall prevent sending prohibited data to external AI or third-party services based on tenant policy.
NFR-PRI-004
The platform shall support data residency restrictions.
NFR-PRI-005
The platform shall maintain data-processing logs and evidence for privacy governance.

Usability and Accessibility
Req ID
Requirement
NFR-UX-001
The analyst workbench shall minimise clicks during triage and investigation.
NFR-UX-002
High-risk actions shall use clear confirmation prompts explaining impact.
NFR-UX-003
Dashboards shall be understandable by non-technical executives.
NFR-UX-004
The UI shall support keyboard navigation, sufficient contrast, visible focus states, and clear labels.
NFR-UX-005
The platform shall provide guided onboarding and connector setup instructions.

Maintainability and Extensibility
Req ID
Requirement
NFR-MA-001
The platform shall be modular with documented APIs and internal contracts.
NFR-MA-002
Connectors, parsers, detections, playbooks, report templates, and compliance packs shall be versioned content.
NFR-MA-003
The codebase shall include automated tests for critical workflows and permission boundaries.
NFR-MA-004
The platform shall support feature flags and controlled rollout.
NFR-MA-005
The platform shall provide developer documentation sufficient for Developers and human engineers.



## 13. Security, Privacy and Multi-Tenancy Requirements

### 13.1 Multi-Tenancy Security Controls
Req ID
Requirement
MT-001
Every request shall be tenant-scoped through verified user/session/API context.
MT-002
Every query shall enforce tenant predicates and permission filters at service and data-access layers.
MT-003
Object storage paths and keys shall include tenant isolation boundaries.
MT-004
Search indexes shall be tenant-partitioned or permission-filtered with tests for cross-tenant leakage.
MT-005
Caches shall be scoped by tenant and user permissions.
MT-006
AI retrieval shall be tenant-scoped and shall not retrieve or embed cross-tenant content.
MT-007
Report templates and scheduled reports shall validate tenant scope at generation time and delivery time.
MT-008
Platform administrators shall require explicit tenant impersonation workflow with reason and audit log if support access is needed.
MT-009
Dedicated tenants shall support separate keys, data stores, or namespaces depending on package.
MT-010
Automated tests shall include negative tests attempting cross-tenant access for all major APIs.


### 13.2 Secure SDLC Requirements
Req ID
Requirement
SSDLC-001
All code shall be peer-reviewed or senior-engineer-reviewed, including AI-generated code.
SSDLC-002
CI/CD shall run unit tests, integration tests, linting, type checks, SAST, dependency scanning, container scanning, and IaC scanning.
SSDLC-003
Production deployments shall require controlled release process with rollback plan.
SSDLC-004
Secrets shall be injected at runtime and never committed.
SSDLC-005
Threat modelling shall be performed for ingestion, identity, multi-tenancy, SOAR actions, AI, report exports, and connectors.
SSDLC-006
Security defects shall be tracked with severity, SLA, owner, and verification.
SSDLC-007
The platform shall maintain SBOM and dependency update process.
SSDLC-008
Penetration testing shall be performed before enterprise launch and after major architectural changes.
SSDLC-009
All privileged admin tools shall be protected from accidental or unauthorised use.
SSDLC-010
Customer-facing security documentation shall be maintained.



## 14. User Journeys and Use Cases
UC-001 - Onboard New SOCaaS Customer
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Tenant admin and onboarding engineer configure customer profile, package, contacts, authority-to-act, critical assets, connectors, test alerts, reports, and go-live sign-off.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.

UC-002 - Connect Microsoft 365/Entra ID
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Tenant admin grants least-privilege permissions; platform validates scopes, tests ingestion, maps identity events, and displays health.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.

UC-003 - Triage New High-Severity Alert
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Tier 1 analyst receives enriched alert, reviews AI summary, checks entity graph, runs playbook steps, escalates or closes with reason.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.

UC-004 - Convert Alert to Incident
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Analyst groups related alerts, creates incident, assigns severity, starts SLA, adds affected assets/users, and notifies customer if required.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.

UC-005 - Customer Approves Containment
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
System sends approval request with evidence and impact; authorised customer approves; SOAR executes action and logs result.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.

UC-006 - Run Threat Hunt
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Tier 3 analyst selects hunt hypothesis, queries telemetry, creates findings, converts confirmed findings to cases, and updates detections.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.


UC-007 - Detection Engineer Tunes Noisy Rule
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Engineer reviews false-positive feedback, tests change, deploys tuned rule to pilot tenants, then promotes to production.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.

UC-008 - Generate Monthly Service Report
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Customer success manager reviews report draft, validates metrics, adds commentary, approves, and distributes securely.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.

UC-009 - Generate Regulatory Evidence Pack
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Compliance manager selects framework, time period, incidents, controls, evidence, and exports regulator/auditor-ready pack.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.

UC-010 - Handle Major Ransomware Incident
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Platform opens war-room, escalates P1, links alerts, runs containment approvals, captures timeline, supports PIR generation.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.

UC-011 - MSSP Creates Downstream Tenant
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Partner admin creates client tenant, applies package template, white-label settings, and assigns partner analyst team.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.

UC-012 - Offboard Customer
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Admin freezes new ingestion, exports agreed data, applies retention/legal hold, revokes connectors, archives tenant, and records closure certificate.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.


UC-013 - AI Drafts Incident Summary
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Analyst requests summary; AI retrieves scoped evidence, drafts facts/inferences/action items, analyst edits and approves.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.

UC-014 - Connector Failure Escalation
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Critical connector fails; platform alerts SOC and customer, creates task, records SLA impact, and shows monitoring gap.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.

UC-015 - Board Views Cyber Posture
Item
Detail
Primary Actor
Defined by use case: customer admin, SOC analyst, detection engineer, compliance manager, MSSP partner or executive.
Goal
Executive user views risk trends, major incidents, remediation status, service performance, and recommendations without raw technical detail.
Preconditions
Actor is authenticated; tenant/package permissions exist; required data sources and policies are configured as applicable.
Main Flow
User starts workflow, platform validates permissions, presents relevant data, captures actions, updates records, logs audit trail, and triggers notifications or next tasks.
Alternate / Exception Flow
Missing permissions, connector unavailable, data incomplete, approval not received, action fails, or SLA breach occurs; system escalates and preserves state.
Acceptance Criteria
Workflow can be completed end-to-end in test environment; audit log captures all material actions; tenant isolation verified; error handling tested.



## 15. Service Packages, Entitlements and Commercial Guardrails

### 15.1 Package Model
Package
Target
Included Capabilities
Commercial Guardrail
Essential Monitor
SME/small agency
Core monitoring, limited assets/logs, basic reports, email escalation, limited connectors.
No high-risk automated response; clear log/asset limits.
Standard SOCaaS
Mid-market/MDA
24/7 monitoring, core identity/endpoint/firewall logs, monthly reports, ticketing, basic playbooks.
Overage billing for log volume and custom integrations.
Advanced MDR
Regulated entity
Expanded logs, EDR/XDR, threat intelligence, response playbooks, quarterly review, compliance pack.
Authority-to-act policy mandatory; senior analyst escalation.
Critical Infrastructure
Bank/telco/utility/major GovTech
Priority queue, custom detections, senior escalation, IR retainer, board dashboard, longer retention.
Minimum annual commitment; stricter onboarding readiness.
Enterprise Private SOC
Large enterprise
Dedicated instance or dedicated data plane, co-managed SOC, custom integrations.
Professional services SOW and support model.
Sovereign SOC
Public-sector/CII national or regional programme
Country-hosted, local compliance pack, sector dashboards, anchor tenant framework.
Formal legal/regulatory positioning; no implied national mandate without authority.
MSSP White-Label
Managed service provider
Partner tenant hierarchy, branding, downstream customer management, partner analyst access.
Partner contract, support obligations, downstream data controls.


### 15.2 Entitlement Requirements
Req ID
Requirement
ENT-001
The platform shall enforce package limits for assets, log volume, connectors, users, retention, reports, AI usage, playbook actions, and response hours.
ENT-002
The platform shall provide customer-visible usage against entitlement.
ENT-003
The platform shall alert internal commercial team before customers exceed limits.
ENT-004
The platform shall require approval for custom scope not included in package.
ENT-005
The platform shall prevent analysts from unknowingly delivering out-of-scope custom work without capturing billable task or exception.
ENT-006
The platform shall support package upgrade/downgrade workflows.
ENT-007
The platform shall preserve historic entitlements for audit and billing dispute resolution.
ENT-008
The platform shall support framework/anchor customers without allowing unlimited customisation to destroy margin.



## 16. MVP, V1, V2 and Enterprise Roadmap
Phase
Indicative Timing
Scope
Phase 0 - Design Mobilisation
0-8 weeks
Final SRS validation, architecture decisions, threat model, UX prototypes, connector priority, vendor choices, delivery governance, founding cyber expert review.
Phase 1 - MVP SOC Core
Months 1-4
Multi-tenant core, auth/RBAC, customer/admin portals, analyst queue, basic alert API/webhook/syslog ingestion, case management, notes/tasks/evidence, basic reports, email/Teams notification, audit logs.
Phase 2 - SOCaaS V1
Months 4-8
Microsoft 365/Entra/Defender connectors, integration health, package entitlements, SLA timers, AI alert summaries, core playbooks, monthly service reports, onboarding workflow.
Phase 3 - MDR/XDR V1
Months 8-14
EDR/firewall/cloud connectors, correlation, entity graph, threat intel, detection-as-code, SOAR approvals, vulnerability context, advanced incident reports.
Phase 4 - Enterprise/Sovereign
Months 14-24
Dedicated tenant/data plane, compliance packs, white-label MSSP, extended retention, advanced dashboards, country deployment templates, sector playbooks.
Phase 5 - Agentic SOC Optimisation
Months 18-30
AI investigation workflows, safe action recommendations, detection tuning assistant, threat hunting copilot, continuous coverage scoring, advanced automation governance.


### 16.1 MVP Must-Have Scope
Tenant/account management
RBAC/MFA basic implementation
Customer/admin/analyst portals
Alert ingestion API, webhook, and syslog collector
Normalized alert model
Case management lifecycle
Tasks, notes, evidence attachments
SLA timers
Audit logging
Basic reporting
Email/Teams notifications
Connector health basics
Package entitlements basics
Secure deployment pipeline
Initial Microsoft connector design
AI summary prototype with strict controls

### 16.2 Deferred from MVP
Full custom SIEM replacement
All vendor connectors
Advanced anomaly detection
Fully autonomous response
Mobile apps
Regulator portal
Advanced white-label marketplace
Full billing integration
Complex OT/industrial monitoring
External cyber insurance integration


## 17. Implementation Plan and Build Governance

### 17.1 Delivery Team
Role
Minimum Responsibility
Product Owner
Owns vision, scope, commercial packages, prioritisation, stakeholder decisions.
Cybersecurity Architect
Defines SOC/XDR architecture, data sources, detection design, response safety, control mapping.
Solution Architect
Defines system architecture, services, APIs, data model, deployment model, scalability.
Senior Full-Stack Engineer
Reviews AI-generated code, sets engineering standards, owns critical modules.
DevSecOps/Cloud Engineer
Builds secure CI/CD, infrastructure, secrets, monitoring, environments.
SOC Operations Lead
Defines shift process, severity, escalation, runbooks, QA and service management.
Detection Engineer
Builds detection library, tuning workflow, MITRE coverage, rule tests.
Data Engineer
Builds ingestion, normalization, storage, parser framework.
UX Designer
Designs analyst-efficient workflows and customer dashboards.
QA/Security Tester
Executes functional, integration, security, permission, performance and regression tests.
Legal/Compliance Advisor
Reviews privacy, data residency, contracts, authority-to-act, liability, reporting obligations.


### 17.2 Coding Governance
Req ID
Requirement
AGENT-001
Developers may generate code, tests, migration scripts, documentation, connector scaffolds, and UI components and ensure to review properly including architecture and review.
AGENT-002
Every generated module shall have tests and code review before merge.
AGENT-003
Security-sensitive modules such as auth, RBAC, tenant isolation, SOAR actions, AI context retrieval, encryption, and secrets shall require additional self review
AGENT-004
Prompts and task tickets shall reference specific SRS requirement IDs.
AGENT-005
All coding output shall be scanned for insecure patterns, dependency risks, licensing issues, and data leakage.
AGENT-006
The product backlog shall maintain traceability between SRS requirements, code modules, tests, and release acceptance.


### 17.3 Environment Strategy
Environment
Purpose
Controls
Local Development
Developer and AI coding agent implementation.
Synthetic data only, no secrets, lint/test hooks.
Shared Dev
Integrated feature testing.
Seed data, mock connectors, ephemeral credentials.
Security Test
Threat modelling validation, SAST/DAST, tenancy tests, abuse tests.
Restricted access, test tenants, exploit simulations.
UAT / Pilot
Customer pilot and SOC process validation.
Limited customer data, sign-off, strict audit.
Production
Live SOC service.
MFA, least privilege, deployment approval, monitoring, backups.
DR
Disaster recovery environment.
Tested restoration, controlled failover, periodic drills.



## 18. Testing, Validation and Acceptance Criteria

### 18.1 Test Categories
Test Category
Coverage
Unit Tests
Business logic, parsers, rule evaluation, API validation, utility functions.
Integration Tests
Connectors, queues, storage, workflow engine, notification systems, AI service calls.
End-to-End Tests
Customer onboarding, alert ingestion to case, incident lifecycle, report generation, approval workflow.
Security Tests
Auth, RBAC/ABAC, tenant isolation, injection, SSRF, secrets, export, audit logs, SOAR action safety.
Performance Tests
Ingestion throughput, queue latency, search, dashboard load, report generation, API rate limits.
Resilience Tests
Connector outage, queue backlog, storage outage, AI service unavailable, partial playbook failure.
Data Quality Tests
Parser mapping, schema drift, unmapped fields, entity resolution, duplicate handling.
AI Evaluation
Grounding, hallucination, unsafe action recommendation, prompt injection, tenant leakage, factual accuracy.
SOC UAT
Analyst triage, escalation, closure, reporting, handover, major incident war-room.
Customer UAT
Portal access, report understanding, approval workflow, tasks, executive dashboard.
Compliance Tests
Evidence pack generation, access review, audit trail completeness, retention policy.
Regression Tests
No breakage to prior features after new connector/rule/playbook release.


### 18.2 Acceptance Gates
Gate
Acceptance Standard
Gate 1 - Architecture
Architecture approved by cyber architect, solution architect, senior engineer, and product owner.
Gate 2 - Secure Foundation
Auth, RBAC, tenant isolation, audit logs, secrets, encryption, CI/CD and baseline infrastructure pass security tests.
Gate 3 - MVP Functional
Core tenant, ingestion, case, task, evidence, reporting, and notifications complete with tests.
Gate 4 - SOC Operational Pilot
SOC analysts can operate sample alerts through triage, escalation, customer notification, and closure.
Gate 5 - Connector Pilot
Priority connectors ingest data reliably and expose health/error/volume metrics.
Gate 6 - AI Safety
AI features pass grounding, permission, prompt injection, and human-approval tests.
Gate 7 - Commercial Pilot
Package entitlements, usage metering, service reports, and customer onboarding run end-to-end.
Gate 8 - Production Readiness
Monitoring, backups, DR plan, incident management, security testing, and runbooks are approved.


### 18.3 Definition of Done
Requirement ID mapped to user story and test cases.
Code reviewed by senior engineer.
Security-sensitive code reviewed by security lead.
Unit/integration tests passed.
Tenant isolation test passed where applicable.
Audit logging implemented where applicable.
Documentation updated.
Operational runbook updated if SOC process affected.
Feature flag and rollback plan created for risky changes.
Product owner accepts feature in UAT.


## 19. Requirements Traceability Matrix
The build backlog shall maintain a live traceability matrix mapping SRS requirement IDs to epics, user stories, code repositories, API endpoints, database tables, test cases, release versions, and operational runbooks. The sample below establishes the required structure.
Req ID
Requirement Area
Epic
Story Mapping
Test Mapping
Phase
TEN-001
Tenant, Organisation and Account Management
Epic-TEN
User stories to be decomposed
Unit + integration + UAT
MVP/V1
IAM-001
Identity, Access Management and Session Security
Epic-IAM
User stories to be decomposed
Unit + integration + UAT
MVP/V1
UI-001
User Experience, Portals and Dashboards
Epic-UI
User stories to be decomposed
Unit + integration + UAT
MVP/V1
ING-001
Data Ingestion, Collection and Connector Framework
Epic-ING
User stories to be decomposed
Unit + integration + UAT
MVP/V1
NORM-001
Normalization, Enrichment and Entity Resolution
Epic-NORM
User stories to be decomposed
Unit + integration + UAT
MVP/V1
DET-001
Detection Engineering and Rules Management
Epic-DET
User stories to be decomposed
Unit + integration + UAT
MVP/V1
COR-001
Alert Correlation, Risk Scoring and Prioritisation
Epic-COR
User stories to be decomposed
Unit + integration + UAT
MVP/V1
CASE-001
Alert, Incident and Case Management
Epic-CASE
User stories to be decomposed
Unit + integration + UAT
MVP/V1
INV-001
Investigation Workbench, Timeline and Entity Graph
Epic-INV
User stories to be decomposed
Unit + integration + UAT
MVP/V1
TI-001
Threat Intelligence Management
Epic-TI
User stories to be decomposed
Unit + integration + UAT
MVP/V1
DATA-001
Cross-cutting control
Epic-Control
Cross-cutting story
Security + audit tests
MVP
CONN-001
Cross-cutting control
Epic-Control
Cross-cutting story
Security + audit tests
MVP
AI-C-001
Cross-cutting control
Epic-Control
Cross-cutting story
Security + audit tests
MVP
OPS-001
Cross-cutting control
Epic-Control
Cross-cutting story
Security + audit tests
MVP
GOV-001
Cross-cutting control
Epic-Control
Cross-cutting story
Security + audit tests
MVP
NFR-SEC-001
Cross-cutting control
Epic-Control
Cross-cutting story
Security + audit tests
MVP
MT-001
Cross-cutting control
Epic-Control
Cross-cutting story
Security + audit tests
MVP
AGENT-001
Cross-cutting control
Epic-Control
Cross-cutting story
Security + audit tests
MVP



## 20. Appendices
Appendix A - Detection Use Case Library Seed
ID
Detection Use Case
Domain
MITRE Tactic
Required Sources
Default Priority
DUC-001
Impossible travel for privileged user
Identity
Credential Access
Entra/Okta/Google Workspace
P2
DUC-002
MFA disabled for privileged account
Identity
Defense Evasion
Entra/Okta
P1
DUC-003
New inbox forwarding rule to external domain
Email/Identity
Collection/Exfiltration
M365/Google Workspace
P2
DUC-004
Suspicious OAuth application consent
Identity/Cloud
Persistence
M365/Entra/Google
P2
DUC-005
Endpoint ransomware behaviour
Endpoint
Impact
Defender/CrowdStrike/SentinelOne/Sophos
P1
DUC-006
Mass file rename/encryption pattern
Endpoint/File
Impact
EDR/Windows logs
P1
DUC-007
Suspicious PowerShell encoded command
Endpoint
Execution
Windows/EDR
P2
DUC-008
Credential dumping tool detected
Endpoint
Credential Access
EDR
P1
DUC-009
Lateral movement using remote services
Endpoint/Network
Lateral Movement
EDR/Windows/Network
P1
DUC-010
New local admin account created
Endpoint/Identity
Persistence/Privilege Escalation
Windows/EDR
P2
DUC-011
Cloud access key created by unusual principal
Cloud
Persistence
AWS/Azure/GCP
P2
DUC-012
Cloud security group opened to world
Cloud/Network
Initial Access
AWS/Azure/GCP
P2
DUC-013
S3/blob bucket made public
Cloud
Exfiltration/Exposure
AWS/Azure/GCP
P2
DUC-014
GuardDuty/SCC/Defender high finding
Cloud
Various
AWS/Azure/GCP
P2
DUC-015
Firewall allowed connection to known C2
Network
Command and Control
Firewall/Threat Intel
P1
DUC-016
Multiple failed VPN logins followed by success
Identity/Network
Initial Access
VPN/Firewall/IdP
P2
DUC-017
Large outbound transfer to new country
Network/Cloud
Exfiltration
Firewall/Proxy/Cloud
P1
DUC-018
DNS tunneling indicator
Network
Command and Control
DNS/Cloudflare/Zscaler
P2
DUC-019
Critical vulnerability exploited on internet-facing asset
Vulnerability/Network
Initial Access
Vuln scanner/WAF/Firewall
P1
DUC-020
Web shell indicator
Endpoint/Web
Persistence
EDR/Web logs
P1
DUC-021
Suspicious email attachment opened
Email/Endpoint
Initial Access
Email security/EDR
P2
DUC-022
User reports phishing and similar messages found
Email
Initial Access
Email platform
P3
DUC-023
Data access spike by insider
Identity/Data
Collection
IdP/DLP/Business API
P2
DUC-024
Admin login from anonymous proxy
Identity
Defense Evasion
IdP/Threat Intel
P2
DUC-025
EDR agent disabled on critical host
Endpoint
Defense Evasion
EDR
P1
DUC-026
Backup deletion or tampering
Endpoint/Cloud
Impact
Cloud/Endpoint/Backup
P1
DUC-027
Suspicious scheduled task creation
Endpoint
Persistence
Windows/EDR
P2
DUC-028
New malicious domain matches tenant email campaign
Threat Intel/Email
Initial Access
TI/Email
P2
DUC-029
OT-adjacent network anomaly
Network/OT
Discovery/Lateral Movement
Network/Syslog/Custom
P1
DUC-030
Connector outage for critical data source
Platform Health
Monitoring Gap
Platform
P2

Appendix B - Initial Product Backlog Seed
Epic ID
Epic
Story ID
User Story
Acceptance Criteria Summary
Phase
EPIC-01
Foundation, Auth and Tenancy
EPIC-01-US-01
As an authorised user, I need foundation, auth and tenancy capability 1 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-01
Foundation, Auth and Tenancy
EPIC-01-US-02
As an authorised user, I need foundation, auth and tenancy capability 2 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-01
Foundation, Auth and Tenancy
EPIC-01-US-03
As an authorised user, I need foundation, auth and tenancy capability 3 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-01
Foundation, Auth and Tenancy
EPIC-01-US-04
As an authorised user, I need foundation, auth and tenancy capability 4 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-01
Foundation, Auth and Tenancy
EPIC-01-US-05
As an authorised user, I need foundation, auth and tenancy capability 5 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-02
Ingestion and Normalisation
EPIC-02-US-01
As an authorised user, I need ingestion and normalisation capability 1 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-02
Ingestion and Normalisation
EPIC-02-US-02
As an authorised user, I need ingestion and normalisation capability 2 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-02
Ingestion and Normalisation
EPIC-02-US-03
As an authorised user, I need ingestion and normalisation capability 3 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-02
Ingestion and Normalisation
EPIC-02-US-04
As an authorised user, I need ingestion and normalisation capability 4 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-02
Ingestion and Normalisation
EPIC-02-US-05
As an authorised user, I need ingestion and normalisation capability 5 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-03
Alert and Case Management
EPIC-03-US-01
As an authorised user, I need alert and case management capability 1 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-03
Alert and Case Management
EPIC-03-US-02
As an authorised user, I need alert and case management capability 2 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-03
Alert and Case Management
EPIC-03-US-03
As an authorised user, I need alert and case management capability 3 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-03
Alert and Case Management
EPIC-03-US-04
As an authorised user, I need alert and case management capability 4 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-03
Alert and Case Management
EPIC-03-US-05
As an authorised user, I need alert and case management capability 5 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-04
Analyst Workbench
EPIC-04-US-01
As an authorised user, I need analyst workbench capability 1 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-04
Analyst Workbench
EPIC-04-US-02
As an authorised user, I need analyst workbench capability 2 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-04
Analyst Workbench
EPIC-04-US-03
As an authorised user, I need analyst workbench capability 3 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-04
Analyst Workbench
EPIC-04-US-04
As an authorised user, I need analyst workbench capability 4 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-04
Analyst Workbench
EPIC-04-US-05
As an authorised user, I need analyst workbench capability 5 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-05
Connector Framework
EPIC-05-US-01
As an authorised user, I need connector framework capability 1 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-05
Connector Framework
EPIC-05-US-02
As an authorised user, I need connector framework capability 2 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-05
Connector Framework
EPIC-05-US-03
As an authorised user, I need connector framework capability 3 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
MVP
EPIC-05
Connector Framework
EPIC-05-US-04
As an authorised user, I need connector framework capability 4 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-05
Connector Framework
EPIC-05-US-05
As an authorised user, I need connector framework capability 5 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-06
Detection Engineering
EPIC-06-US-01
As an authorised user, I need detection engineering capability 1 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-06
Detection Engineering
EPIC-06-US-02
As an authorised user, I need detection engineering capability 2 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-06
Detection Engineering
EPIC-06-US-03
As an authorised user, I need detection engineering capability 3 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-06
Detection Engineering
EPIC-06-US-04
As an authorised user, I need detection engineering capability 4 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-06
Detection Engineering
EPIC-06-US-05
As an authorised user, I need detection engineering capability 5 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-07
SOAR and Playbooks
EPIC-07-US-01
As an authorised user, I need soar and playbooks capability 1 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-07
SOAR and Playbooks
EPIC-07-US-02
As an authorised user, I need soar and playbooks capability 2 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-07
SOAR and Playbooks
EPIC-07-US-03
As an authorised user, I need soar and playbooks capability 3 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-07
SOAR and Playbooks
EPIC-07-US-04
As an authorised user, I need soar and playbooks capability 4 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-07
SOAR and Playbooks
EPIC-07-US-05
As an authorised user, I need soar and playbooks capability 5 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-08
AI Copilot
EPIC-08-US-01
As an authorised user, I need ai copilot capability 1 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-08
AI Copilot
EPIC-08-US-02
As an authorised user, I need ai copilot capability 2 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-08
AI Copilot
EPIC-08-US-03
As an authorised user, I need ai copilot capability 3 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-08
AI Copilot
EPIC-08-US-04
As an authorised user, I need ai copilot capability 4 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-08
AI Copilot
EPIC-08-US-05
As an authorised user, I need ai copilot capability 5 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-09
Reporting and Evidence Packs
EPIC-09-US-01
As an authorised user, I need reporting and evidence packs capability 1 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-09
Reporting and Evidence Packs
EPIC-09-US-02
As an authorised user, I need reporting and evidence packs capability 2 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-09
Reporting and Evidence Packs
EPIC-09-US-03
As an authorised user, I need reporting and evidence packs capability 3 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-09
Reporting and Evidence Packs
EPIC-09-US-04
As an authorised user, I need reporting and evidence packs capability 4 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-09
Reporting and Evidence Packs
EPIC-09-US-05
As an authorised user, I need reporting and evidence packs capability 5 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-10
Compliance and Governance
EPIC-10-US-01
As an authorised user, I need compliance and governance capability 1 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-10
Compliance and Governance
EPIC-10-US-02
As an authorised user, I need compliance and governance capability 2 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-10
Compliance and Governance
EPIC-10-US-03
As an authorised user, I need compliance and governance capability 3 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-10
Compliance and Governance
EPIC-10-US-04
As an authorised user, I need compliance and governance capability 4 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-10
Compliance and Governance
EPIC-10-US-05
As an authorised user, I need compliance and governance capability 5 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-11
Packages and Billing
EPIC-11-US-01
As an authorised user, I need packages and billing capability 1 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-11
Packages and Billing
EPIC-11-US-02
As an authorised user, I need packages and billing capability 2 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-11
Packages and Billing
EPIC-11-US-03
As an authorised user, I need packages and billing capability 3 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-11
Packages and Billing
EPIC-11-US-04
As an authorised user, I need packages and billing capability 4 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-11
Packages and Billing
EPIC-11-US-05
As an authorised user, I need packages and billing capability 5 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-12
MSSP/Sovereign/Enterprise Deployment
EPIC-12-US-01
As an authorised user, I need mssp/sovereign/enterprise deployment capability 1 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-12
MSSP/Sovereign/Enterprise Deployment
EPIC-12-US-02
As an authorised user, I need mssp/sovereign/enterprise deployment capability 2 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-12
MSSP/Sovereign/Enterprise Deployment
EPIC-12-US-03
As an authorised user, I need mssp/sovereign/enterprise deployment capability 3 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-12
MSSP/Sovereign/Enterprise Deployment
EPIC-12-US-04
As an authorised user, I need mssp/sovereign/enterprise deployment capability 4 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2
EPIC-12
MSSP/Sovereign/Enterprise Deployment
EPIC-12-US-05
As an authorised user, I need mssp/sovereign/enterprise deployment capability 5 so that the platform can deliver secure SOC operations.
Acceptance criteria shall reference SRS requirement IDs, permissions, audit logging, tests, and tenant isolation where applicable.
V1/V2


Appendix C - Data Dictionary Seed
Entity
Field
Type
Description
Requirement
Owner
Tenant
id
UUID/string
Unique record identifier
Required
System
Tenant
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Tenant
created_at/updated_at
timestamp
Audit timestamps
Required
System
User
id
UUID/string
Unique record identifier
Required
System
User
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
User
created_at/updated_at
timestamp
Audit timestamps
Required
System
Role/Permission
id
UUID/string
Unique record identifier
Required
System
Role/Permission
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Role/Permission
created_at/updated_at
timestamp
Audit timestamps
Required
System
Integration
id
UUID/string
Unique record identifier
Required
System
Integration
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Integration
created_at/updated_at
timestamp
Audit timestamps
Required
System
Collector
id
UUID/string
Unique record identifier
Required
System
Collector
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Collector
created_at/updated_at
timestamp
Audit timestamps
Required
System
Raw Event
id
UUID/string
Unique record identifier
Required
System
Raw Event
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Raw Event
created_at/updated_at
timestamp
Audit timestamps
Required
System
Normalized Event
id
UUID/string
Unique record identifier
Required
System
Normalized Event
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Normalized Event
created_at/updated_at
timestamp
Audit timestamps
Required
System
Alert
id
UUID/string
Unique record identifier
Required
System
Alert
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Alert
created_at/updated_at
timestamp
Audit timestamps
Required
System
Incident/Case
id
UUID/string
Unique record identifier
Required
System
Incident/Case
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Incident/Case
created_at/updated_at
timestamp
Audit timestamps
Required
System
Entity
id
UUID/string
Unique record identifier
Required
System
Entity
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Entity
created_at/updated_at
timestamp
Audit timestamps
Required
System
Asset
id
UUID/string
Unique record identifier
Required
System
Asset
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Asset
created_at/updated_at
timestamp
Audit timestamps
Required
System
Vulnerability
id
UUID/string
Unique record identifier
Required
System
Vulnerability
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Vulnerability
created_at/updated_at
timestamp
Audit timestamps
Required
System
Detection Rule
id
UUID/string
Unique record identifier
Required
System
Detection Rule
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Detection Rule
created_at/updated_at
timestamp
Audit timestamps
Required
System
Playbook
id
UUID/string
Unique record identifier
Required
System
Playbook
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Playbook
created_at/updated_at
timestamp
Audit timestamps
Required
System
Threat Intelligence Object
id
UUID/string
Unique record identifier
Required
System
Threat Intelligence Object
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Threat Intelligence Object
created_at/updated_at
timestamp
Audit timestamps
Required
System
Evidence Item
id
UUID/string
Unique record identifier
Required
System
Evidence Item
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Evidence Item
created_at/updated_at
timestamp
Audit timestamps
Required
System
Report
id
UUID/string
Unique record identifier
Required
System
Report
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Report
created_at/updated_at
timestamp
Audit timestamps
Required
System
Audit Log
id
UUID/string
Unique record identifier
Required
System
Audit Log
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Audit Log
created_at/updated_at
timestamp
Audit timestamps
Required
System
Billing Usage Record
id
UUID/string
Unique record identifier
Required
System
Billing Usage Record
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Billing Usage Record
created_at/updated_at
timestamp
Audit timestamps
Required
System
Compliance Evidence Record
id
UUID/string
Unique record identifier
Required
System
Compliance Evidence Record
tenant_id
UUID/string
Tenant partition identifier
Required except global templates
System
Compliance Evidence Record
created_at/updated_at
timestamp
Audit timestamps
Required
System

Appendix D - Open Decisions for Expert Review
ID
Decision Required
OD-001
Final event analytics backend: OpenSearch vs ClickHouse vs Elastic vs Snowflake/BigQuery per deployment model.
OD-002
Final AI provider/private model strategy per country and regulated customer type.
OD-003
Whether to build proprietary SIEM-lite in MVP or rely on external SIEM for deeper log search initially.
OD-004
Customer-side collector technology and update model.
OD-005
Minimum cyber certifications and accreditations required before selling to regulated sectors.
OD-006
Legal authority-to-act templates and liability caps.
OD-007
Country-specific regulatory packs and data-residency strategy.
OD-008
Pricing and overage model for log volume, storage, AI use, and analyst time.
OD-009
24/7 SOC staffing model: in-house, hybrid, partner, or phased managed operations.
OD-010
Incident response retainer scope and exclusions.
OD-011
Threat intelligence feed selection and budget.
OD-012
Whether to support mobile incident approval app in V2.
OD-013
Target first three client segments and anchor customer onboarding sequence.
OD-014
Third-party penetration test provider and readiness timeline.
OD-015
Data retention defaults by package and jurisdiction.

Appendix E - Bibliography and Source Notes
Source
URL / Note
NIST Cybersecurity Framework 2.0
https://www.nist.gov/cyberframework
NIST CSWP 29, Cybersecurity Framework 2.0 PDF
https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide - archived/withdrawn status should be checked before final implementation
https://csrc.nist.gov/pubs/sp/800/61/r2/final
MITRE ATT&CK
https://attack.mitre.org/
OCSF
https://ocsf.io/
Sigma Detection Format
https://sigmahq.io/
Sigma rule documentation
https://sigmahq.io/docs/basics/rules.html
OASIS STIX/TAXII 2.1
https://www.oasis-open.org/standard/taxii-version-2-1/
FIRST TLP
https://www.first.org/tlp/
CIS Controls
https://www.cisecurity.org/controls
Reference customer concept paper

End of SRS. This document is intentionally comprehensive, but the final production version should be validated in workshops with cybersecurity architecture, SOC operations, detection engineering, data engineering, cloud security, legal/compliance, and commercial stakeholders before build execution.

Appendix F - Detailed Screen and UX Requirements
The following screen catalogue is intended to prevent under-scoping of the build. Each screen must be represented in wireframes, user stories, role-permission rules, audit requirements, and acceptance tests before development starts.
ID
Screen
Primary Users
Required Content
Acceptance Notes
SCR-001
Login and MFA
All users
Login, password reset, MFA challenge, SSO entry, session expiry notice, suspicious login warning.
No tenant data rendered before authentication; failed attempts logged; SSO/MFA errors clear.
SCR-002
Tenant Switcher
Internal/MSSP users
Switch authorised tenant context, search tenants, see tenant status and package.
Explicit tenant context visible; support impersonation requires reason and audit.
SCR-003
Customer Home Dashboard
Customer users
Incident summary, risk score, integration health, open tasks, approvals, reports.
Shows only customer-visible content; explains monitoring gaps.
SCR-004
Executive Dashboard
Executive viewer
Board KPIs, major risks, SLA trends, recurring themes, recommendations.
Business language; no raw sensitive logs by default.
SCR-005
SOC Command Queue
SOC analysts
Queue by severity, SLA, tenant, status, data source, assigned analyst, age.
Priority sorting, bulk triage guardrails, no cross-tenant leakage.
SCR-006
Alert Detail
SOC analysts/customer technical users
Alert summary, raw source, normalized fields, entities, enrichment, actions.
Customer view filtered; analyst view includes internal notes.
SCR-007
Incident Case Detail
All case roles
Lifecycle, timeline, evidence, tasks, notes, communications, SLA, approvals.
Full audit trail; status transitions validated.
SCR-008
Investigation Timeline
Analysts/IR
Chronological events, filters, source/ingest times, analyst actions, playbook steps.
Preserve time zones and uncertainty; export controlled.
SCR-009
Entity Graph
Analysts
Users, hosts, IPs, domains, files, cloud resources, vulnerabilities, incidents.
Graph confidence shown; inferred links distinguished.
SCR-010
Evidence Locker
Analysts/compliance
Evidence files, hashes, chain-of-custody, classification, report inclusion.
Immutable metadata; deletion restricted.
SCR-011
SOAR Approval Screen
Customer approvers/SOC managers
Recommended action, impact, evidence, expiry, approval/rejection, comments.
High-impact actions require clear warning and identity confirmation.
SCR-012
Playbook Designer
SOC managers/detection engineers
Triggers, steps, approvals, actions, branches, error handling, simulation.
Versioned drafts; production publish requires approval.
SCR-013
Detection Rule Editor
Detection engineers
Rule code, metadata, mapping, tests, severity, playbook, deployment scope.
Syntax validation, test execution, version history.
SCR-014
Detection Coverage Dashboard
SOC/detection leadership
MITRE coverage, data source dependencies, gaps, noisy rules, FP rates.
Coverage must show prerequisites and limitations.
SCR-015
Threat Intel Console
Threat intel analysts
Indicators, campaigns, confidence, TLP, expiry, sightings, related cases.
Low-confidence indicators cannot auto-block without policy.
SCR-016
Connector Marketplace
Tenant/admin users
Available connectors, setup status, required permissions, package availability.
Unsupported connectors show roadmap/request option.
SCR-017
Connector Setup Wizard
Tenant admins/onboarding
Auth, scopes, validation, test event, mapping confirmation, health.
Least privilege instructions and permission risk displayed.
SCR-018
Integration Health Dashboard
SOC/onboarding/customer
Last event, lag, errors, volume, credential expiry, data-source priority.
Critical failures escalate and show monitoring gap.
SCR-019
Asset Inventory
Customer/SOC
Assets, owners, criticality, tags, vulnerabilities, incidents, source confidence.
Bulk edit guarded; stale assets flagged.
SCR-020
Identity Inventory
Customer/SOC
Users, privileged accounts, MFA, groups, risky sign-ins, incidents.
Sensitive identity data role-restricted.
SCR-021
Vulnerability/Exposure Dashboard
Customer/SOC
Vulns by severity, exploitability, asset criticality, remediation tasks.
Prioritisation explained; customer task creation supported.
SCR-022
Reports Library
Customer/compliance
Generated reports, drafts, schedules, approval status, downloads.
Download logged; report scope visible.
SCR-023
Report Builder
Compliance/customer success
Template, period, incidents, metrics, evidence, commentary, recipients.
Large reports async; exports permission-filtered.
SCR-024
Compliance Mapping
Compliance users
Frameworks, controls, evidence, owners, gaps, exceptions, due dates.
Templates configurable by country/sector.
SCR-025
Tenant Settings
Tenant admins
Profile, contacts, escalation matrix, business hours, data retention, authority-to-act.
Material changes require audit and sometimes approval.
SCR-026
Package & Usage
Customer/internal finance
Entitlements, usage, overage risk, log volume, connectors, assets, reports.
Commercial boundaries clear; internal margin view hidden from customer.
SCR-027
MSSP Partner Console
Partner admins
Downstream tenants, branding, analyst allocation, package templates, partner reports.
Partner users cannot access platform global admin controls.
SCR-028
Platform Admin Console
Super admins
Global settings, feature flags, content packs, tenants, system status.
Privileged actions require strong audit.
SCR-029
Audit Log Search
Compliance/security
User actions, system actions, AI, exports, admin, SOAR actions.
Tamper-evident, filterable, export controlled.
SCR-030
AI Copilot Panel
Analysts/customer success
Summary, recommended next steps, report draft, query assistant, confidence.
Evidence-linked outputs; unsafe recommendations reportable.
SCR-031
Major Incident War Room
Incident responders
Roles, live timeline, comms, tasks, approvals, customer updates, decision log.
P1 mode with escalation and communication discipline.
SCR-032
Customer Onboarding Workspace
Onboarding team
Checklist, data sources, test alerts, contacts, assets, baselines, go-live.
No production monitoring until mandatory checklist complete.
SCR-033
Knowledge Base
SOC/customer
Playbooks, advisories, customer guidance, analyst notes, FAQs.
Versioned, searchable, customer-visible tagging.
SCR-034
Release Notes / Status
All users
Platform status, scheduled maintenance, release notes, known issues.
Customer-visible and internal versions separated.
SCR-035
Support Request Screen
Customer/admin
Platform issue, connector issue, report request, feature request, billing issue.
Support SLA linked to package.


Appendix G - API and Service Interface Requirements
The API catalogue below is a build seed. Final endpoint names may change, but the product must expose equivalent capabilities with authentication, authorization, validation, rate limiting, idempotency for writes where appropriate, error codes, audit logs, and tenant scoping.
ID
Domain
Method
Indicative Endpoint
Purpose
Security/Acceptance
API-TEN-001
Tenant
POST
/tenant/create-tenant
Create tenant
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-TEN-002
Tenant
PATCH
/tenant/update-tenant-profile
Update tenant profile
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-TEN-003
Tenant
GET
/tenant/get-tenant-settings
Get tenant settings
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-TEN-004
Tenant
GET
/tenant/list-tenant-users
List tenant users
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-TEN-005
Tenant
PATCH
/tenant/archive-tenant
Archive tenant
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-TEN-006
Tenant
POST
/tenant/export-tenant-data
Export tenant data
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-TEN-007
Tenant
PATCH
/tenant/set-package
Set package
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-TEN-008
Tenant
PATCH
/tenant/set-data-residency
Set data residency
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-TEN-009
Tenant
PATCH
/tenant/set-retention-policy
Set retention policy
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-TEN-010
Tenant
GET
/tenant/get-tenant-health
Get tenant health
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-IDE-001
Identity
PATCH
/identity/invite-user
Invite user
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-IDE-002
Identity
PATCH
/identity/deactivate-user
Deactivate user
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-IDE-003
Identity
PATCH
/identity/assign-role
Assign role
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-IDE-004
Identity
PATCH
/identity/remove-role
Remove role
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-IDE-005
Identity
GET
/identity/get-access-review
Get access review
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-IDE-006
Identity
POST
/identity/create-api-token
Create API token
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-IDE-007
Identity
POST
/identity/rotate-api-token
Rotate API token
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-IDE-008
Identity
PATCH
/identity/revoke-api-token
Revoke API token
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-IDE-009
Identity
PATCH
/identity/start-sso-config
Start SSO config
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-IDE-010
Identity
PATCH
/identity/validate-sso-config
Validate SSO config
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ING-001
Ingestion
PATCH
/ingestion/post-alert
Post alert
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ING-002
Ingestion
PATCH
/ingestion/post-event-batch
Post event batch
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ING-003
Ingestion
PATCH
/ingestion/post-webhook-event
Post webhook event
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ING-004
Ingestion
PATCH
/ingestion/register-collector
Register collector
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ING-005
Ingestion
GET
/ingestion/get-collector-config
Get collector config
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ING-006
Ingestion
PATCH
/ingestion/update-collector-health
Update collector health
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ING-007
Ingestion
GET
/ingestion/get-ingestion-status
Get ingestion status
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ING-008
Ingestion
PATCH
/ingestion/replay-event-batch
Replay event batch
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ING-009
Ingestion
GET
/ingestion/get-parser-errors
Get parser errors
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ING-010
Ingestion
PATCH
/ingestion/acknowledge-source-outage
Acknowledge source outage
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-CAS-001
Case
POST
/case/create-alert
Create alert
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-CAS-002
Case
GET
/case/get-alert
Get alert
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-CAS-003
Case
PATCH
/case/update-alert-disposition
Update alert disposition
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-CAS-004
Case
POST
/case/create-incident
Create incident
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-CAS-005
Case
PATCH
/case/update-incident
Update incident
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-CAS-006
Case
PATCH
/case/assign-case
Assign case
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-CAS-007
Case
PATCH
/case/add-note
Add note
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-CAS-008
Case
PATCH
/case/add-task
Add task
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-CAS-009
Case
PATCH
/case/attach-evidence
Attach evidence
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-CAS-010
Case
PATCH
/case/close-incident
Close incident
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-INV-001
Investigation
PATCH
/investigation/search-events
Search events
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-INV-002
Investigation
GET
/investigation/get-entity-profile
Get entity profile
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-INV-003
Investigation
GET
/investigation/get-entity-graph
Get entity graph
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-INV-004
Investigation
GET
/investigation/get-timeline
Get timeline
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-INV-005
Investigation
PATCH
/investigation/save-query
Save query
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-INV-006
Investigation
POST
/investigation/run-hunt-query
Run hunt query
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-INV-007
Investigation
POST
/investigation/export-evidence-subset
Export evidence subset
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-INV-008
Investigation
POST
/investigation/create-finding
Create finding
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-INV-009
Investigation
PATCH
/investigation/link-related-case
Link related case
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-INV-010
Investigation
GET
/investigation/get-raw-event
Get raw event
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-DET-001
Detection
POST
/detection/create-rule
Create rule
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-DET-002
Detection
PATCH
/detection/test-rule
Test rule
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-DET-003
Detection
PATCH
/detection/review-rule
Review rule
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-DET-004
Detection
PATCH
/detection/deploy-rule
Deploy rule
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-DET-005
Detection
PATCH
/detection/rollback-rule
Rollback rule
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-DET-006
Detection
GET
/detection/get-rule-coverage
Get rule coverage
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-DET-007
Detection
GET
/detection/list-false-positives
List false positives
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-DET-008
Detection
PATCH
/detection/submit-tuning-feedback
Submit tuning feedback
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-DET-009
Detection
PATCH
/detection/retire-rule
Retire rule
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-DET-010
Detection
POST
/detection/export-rule-pack
Export rule pack
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-PLA-001
Playbook
POST
/playbook/create-playbook
Create playbook
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-PLA-002
Playbook
PATCH
/playbook/simulate-playbook
Simulate playbook
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-PLA-003
Playbook
PATCH
/playbook/publish-playbook
Publish playbook
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-PLA-004
Playbook
POST
/playbook/execute-playbook
Execute playbook
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-PLA-005
Playbook
POST
/playbook/approve-action
Approve action
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-PLA-006
Playbook
POST
/playbook/reject-action
Reject action
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-PLA-007
Playbook
GET
/playbook/get-execution-log
Get execution log
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-PLA-008
Playbook
PATCH
/playbook/cancel-execution
Cancel execution
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-PLA-009
Playbook
PATCH
/playbook/rollback-guidance
Rollback guidance
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-PLA-010
Playbook
GET
/playbook/list-action-catalog
List action catalog
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-AI-001
AI
POST
/ai/summarise-alert
Summarise alert
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-AI-002
AI
POST
/ai/summarise-incident
Summarise incident
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-AI-003
AI
POST
/ai/draft-customer-update
Draft customer update
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-AI-004
AI
POST
/ai/draft-pir
Draft PIR
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-AI-005
AI
PATCH
/ai/suggest-rule-tuning
Suggest rule tuning
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-AI-006
AI
POST
/ai/generate-query
Generate query
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-AI-007
AI
PATCH
/ai/explain-threat-intel
Explain threat intel
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-AI-008
AI
PATCH
/ai/evaluate-output-feedback
Evaluate output feedback
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-AI-009
AI
GET
/ai/get-prompt-log
Get prompt log
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-AI-010
AI
PATCH
/ai/set-ai-policy
Set AI policy
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-REP-001
Reporting
POST
/reporting/create-report-draft
Create report draft
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-REP-002
Reporting
POST
/reporting/generate-report
Generate report
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-REP-003
Reporting
POST
/reporting/approve-report
Approve report
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-REP-004
Reporting
PATCH
/reporting/download-report
Download report
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-REP-005
Reporting
PATCH
/reporting/schedule-report
Schedule report
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-REP-006
Reporting
GET
/reporting/list-report-templates
List report templates
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-REP-007
Reporting
POST
/reporting/create-evidence-pack
Create evidence pack
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-REP-008
Reporting
POST
/reporting/export-csv
Export CSV
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-REP-009
Reporting
GET
/reporting/get-dashboard-metrics
Get dashboard metrics
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-REP-010
Reporting
PATCH
/reporting/revoke-report-link
Revoke report link
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-COM-001
Compliance
POST
/compliance/create-framework
Create framework
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-COM-002
Compliance
PATCH
/compliance/map-control
Map control
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-COM-003
Compliance
PATCH
/compliance/attach-evidence
Attach evidence
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-COM-004
Compliance
POST
/compliance/create-exception
Create exception
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-COM-005
Compliance
POST
/compliance/approve-risk-acceptance
Approve risk acceptance
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-COM-006
Compliance
GET
/compliance/get-evidence-freshness
Get evidence freshness
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-COM-007
Compliance
POST
/compliance/export-audit-pack
Export audit pack
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-COM-008
Compliance
GET
/compliance/list-regulatory-reports
List regulatory reports
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-COM-009
Compliance
PATCH
/compliance/update-due-date
Update due date
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-COM-010
Compliance
PATCH
/compliance/close-audit-request
Close audit request
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-BIL-001
Billing
GET
/billing/get-usage
Get usage
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-BIL-002
Billing
GET
/billing/get-entitlements
Get entitlements
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-BIL-003
Billing
PATCH
/billing/update-entitlement
Update entitlement
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-BIL-004
Billing
POST
/billing/create-overage-alert
Create overage alert
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-BIL-005
Billing
POST
/billing/export-billing-usage
Export billing usage
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-BIL-006
Billing
POST
/billing/record-service-hours
Record service hours
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-BIL-007
Billing
POST
/billing/create-addon-service
Create addon service
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-BIL-008
Billing
PATCH
/billing/set-framework-minimum
Set framework minimum
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-BIL-009
Billing
GET
/billing/get-margin-view
Get margin view
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-BIL-010
Billing
PATCH
/billing/suspend-service
Suspend service
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ADM-001
Admin
GET
/admin/list-tenants
List tenants
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ADM-002
Admin
GET
/admin/get-system-health
Get system health
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ADM-003
Admin
PATCH
/admin/set-feature-flag
Set feature flag
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ADM-004
Admin
PATCH
/admin/manage-content-pack
Manage content pack
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ADM-005
Admin
POST
/admin/run-data-repair-job
Run data repair job
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ADM-006
Admin
GET
/admin/get-audit-log
Get audit log
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ADM-007
Admin
PATCH
/admin/set-global-policy
Set global policy
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ADM-008
Admin
POST
/admin/rotate-platform-key
Rotate platform key
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ADM-009
Admin
POST
/admin/create-maintenance-banner
Create maintenance banner
Tenant scoped; RBAC/ABAC enforced; audit where material.
API-ADM-010
Admin
GET
/admin/get-release-status
Get release status
Tenant scoped; RBAC/ABAC enforced; audit where material.


Appendix H - Data Model Table Catalogue
The table catalogue below provides enough structure for the initial database design and domain model. Final physical schemas may vary by data store, but logical ownership, retention, tenant scope, and security classification must be preserved.
Table
Purpose
Key Fields
Retention
Classification
tenants
Customer/partner/deployment partition
tenant_id, parent_tenant_id, name, status, package_id, region, data_residency, created_at
Permanent + retention rules
High
tenant_settings
Tenant configuration
tenant_id, escalation_matrix, business_hours, authority_policy, retention_policy
Life of tenant
High
users
Platform users
user_id, tenant_id, email, name, status, mfa_status, last_login
Life of account + audit retention
High
roles
Role definitions
role_id, name, scope, description
Permanent
Medium
user_roles
User role assignments
user_id, role_id, tenant_id, assigned_by, assigned_at
Life + audit
High
api_tokens
Machine credentials metadata
token_id, tenant_id, scopes, expiry, status, last_used
Until revoked + audit
High
integrations
Connector configuration metadata
integration_id, tenant_id, type, status, scopes, health, last_success
Life of connector
High
connector_secrets
Encrypted references only
secret_ref, integration_id, vault_path, rotation_due
Life of connector
Restricted
collectors
Collector inventory
collector_id, tenant_id, version, host, status, last_seen
Life of collector
High
raw_events
Raw payload metadata
raw_id, tenant_id, source, object_ref, hash, ingest_time
Policy based
Restricted
normalized_events
Canonical events
event_id, tenant_id, source, event_time, category, activity, severity, entity_refs
Hot/warm retention
High
alerts
Security alerts
alert_id, tenant_id, severity, status, rule_id, source, risk_score
Case retention
High
incidents
Cases/incidents
incident_id, tenant_id, severity, status, owner, sla_due, disposition
Case retention
High
incident_alerts
Alert-case links
incident_id, alert_id, link_type
Case retention
High
incident_timeline
Timeline entries
entry_id, incident_id, time, type, summary, source_ref
Case retention
High
case_notes
Notes
note_id, incident_id, author, visibility, body, created_at
Case retention
High
case_tasks
Tasks
task_id, incident_id, assignee, status, due_at, outcome
Case retention
Medium
evidence_items
Evidence artifacts
evidence_id, incident_id, object_ref, hash, classification, custody
Legal/evidence retention
Restricted
assets
Asset inventory
asset_id, tenant_id, type, hostname, owner, criticality, confidence
Life of asset + history
High
identities
Identity inventory
identity_id, tenant_id, upn, privilege, mfa, status, risk
Policy based
High
vulnerabilities
Vulnerability findings
vuln_id, tenant_id, cve, severity, exploitability, status
Policy based
Medium
asset_vulnerabilities
Asset-vulnerability mapping
asset_id, vuln_id, first_seen, last_seen, status
Policy based
Medium
detection_rules
Rules
rule_id, version, status, severity, logic_ref, owner, mitre
Permanent + versions
Medium
rule_tests
Rule tests
test_id, rule_id, input_ref, expected, result
Permanent
Medium
rule_feedback
FP/tuning feedback
feedback_id, rule_id, alert_id, reason, submitted_by
Rule lifecycle
Medium
playbooks
Playbook definitions
playbook_id, version, status, trigger, owner
Permanent + versions
Medium
playbook_executions
Run logs
execution_id, playbook_id, incident_id, status, started_at, ended_at
Audit retention
High
approval_requests
Action approvals
approval_id, action, risk_class, approver, status, expiry
Audit retention
High
action_catalog
Allowed response actions
action_id, class, connector, permissions, rollback_guidance
Permanent
Medium
threat_intel_objects
Intel objects
intel_id, type, value, source, confidence, tlp, expiry
Intel retention
Medium
intel_sightings
Indicator sightings
sighting_id, intel_id, tenant_id, event_ref, first_seen
Policy based
Medium
reports
Reports metadata
report_id, tenant_id, template, status, period, object_ref
Report retention
High
report_downloads
Download audit
download_id, report_id, user_id, time, ip
Audit retention
High
compliance_controls
Controls
control_id, framework, requirement, owner
Permanent
Medium
control_mappings
Evidence mappings
control_id, evidence_id, incident_id, status
Compliance retention
Medium
audit_logs
Audit events
audit_id, tenant_id, actor, action, target, time, result
Immutable retention
Restricted
usage_records
Billing/metering
usage_id, tenant_id, metric, quantity, period
Finance retention
Medium
service_hours
Professional services tracking
record_id, tenant_id, service_type, hours, case_ref
Finance retention
Medium
feature_flags
Feature configuration
flag_id, scope, value, rollout, owner
Permanent + history
Medium
system_health
Platform health metrics
metric_id, service, status, latency, errors, time
Operational retention
Low


Appendix I - Detailed Connector Specifications
Connector
Inbound Data
Outbound Actions
Authentication
Implementation Notes
Microsoft 365
Audit logs, email events, mailbox rules, user activity, security alerts.
Quarantine email, search mailbox, create investigation task where permissions allow.
OAuth app registration with least-privilege Graph/API permissions.
High MVP priority due to common adoption and phishing/BEC value.
Entra ID
Sign-ins, risky users, group changes, privilege changes, MFA status, app consent.
Disable user, revoke sessions, require password reset, remove risky app consent where allowed.
OAuth / Graph permissions; privileged actions separated from read-only ingestion.
Identity is core to modern attacks.
Microsoft Defender
Endpoint alerts, device info, vulnerabilities, investigation package, incidents.
Isolate device, collect package, run AV scan where pre-authorised.
OAuth security API permissions; action permissions separately gated.
Primary early EDR connector.
Microsoft Sentinel
Incidents, alerts, analytics rule outputs, log query handoff.
Create/update incident, sync comments, run approved query if configured.
Azure app registration and workspace permissions.
Useful where customer already has SIEM investment.
CrowdStrike Falcon
Detections, hosts, users, behaviours, incidents.
Contain host, lift containment, add IOC where authorised.
OAuth client credentials; action scopes separately configured.
Advanced MDR tier.
SentinelOne
Threats, agents, endpoints, alerts.
Isolate endpoint, kill/quarantine where authorised.
API token/OAuth depending deployment.
Advanced MDR tier.
Sophos
Endpoint alerts, server/workload alerts, email/network events where available.
Endpoint isolation/remediation where supported.
API credentials and tenant-specific scopes.
SME/mid-market value.
Fortinet
Firewall/syslog, FortiAnalyzer alerts, VPN logs, blocked traffic.
Block IP/domain, update address group where authorised.
Syslog/API; TLS and IP allowlisting.
Network monitoring core.
Palo Alto
Firewall traffic/threat logs, Prisma/Cortex alerts where licensed.
Block indicators, update security policies where authorised.
API key/OAuth; policy action carefully controlled.
Enterprise/critical tier.
Cisco
Meraki, Umbrella, Secure Endpoint, firewall/network alerts depending product.
Block domain/IP, create incident, update policy where authorised.
Product-specific APIs.
Phase 3 due to product family breadth.
Okta
Sign-ins, user lifecycle, MFA events, app assignments, suspicious activity.
Suspend user, reset factors, revoke sessions where authorised.
API token/OAuth with least privilege.
Important for enterprises outside Microsoft identity.
Google Workspace
Admin audit, login audit, Gmail audit, Drive activity, alert center.
Suspend user, revoke token, investigate email where authorised.
OAuth service account/domain-wide delegation.
Important for SME/startup/public sector using Google.
AWS
CloudTrail, GuardDuty, IAM, Config, Security Hub, EC2/S3/Lambda context.
Disable key, apply security group change, tag resource, create ticket.
Cross-account role with external ID and least privilege.
Cloud tier.
Azure
Activity logs, Defender for Cloud, IAM, resource inventory.
Disable credential, update NSG, tag resource, create remediation task.
Azure app/managed identity permissions.
Cloud tier and Microsoft ecosystem.
GCP
Cloud Audit Logs, Security Command Center, IAM, asset inventory.
Disable service account key, update firewall, create ticket.
Service account with least privilege.
Phase 3 cloud.
Cloudflare
DNS, WAF, Access, Zero Trust logs, blocked traffic.
Block IP/domain, update WAF list, create Zero Trust action.
API token with scoped permissions.
Edge and web app monitoring.
Zscaler
Web access logs, private access, cloud firewall events.
Block URL/category, create ticket; automated changes cautiously gated.
API credentials / log streaming.
SASE tier.
ServiceNow
Incidents, tasks, change context, CMDB.
Create/update tickets, sync status/comments, link cases.
OAuth/basic/service account.
Enterprise workflow sync.
Jira
Issues, tasks, project workflows.
Create/update issues, sync comments/status.
OAuth/API token.
Useful for tech teams and remediation.
Slack
Notifications, approvals, war-room channels.
Send message, request approval, create channel where allowed.
OAuth bot app.
Communication channel.
Teams
Notifications, approvals, war-room channels.
Send message/card, request approval, create channel where allowed.
Graph app permissions.
Communication channel.
Vulnerability Scanner
Findings, assets, severity, exploitability, scan status.
Create remediation task, update exception.
API credentials per vendor.
Exposure context and add-on service.
Syslog
Network/device/server logs from many products.
Inbound only in MVP; response through specific connector or manual task.
TLS syslog, collector certificate, parsing profile.
Broadest initial coverage.
Customer API
Sector-specific events and custom systems.
Custom actions by SOW only.
Mutual TLS/API token/OAuth.
Requires specification and professional services.


Appendix J - Detailed Playbook Step Templates
Step ID
Playbook
Step
Inputs
Outputs/Acceptance
PB-001-01
Phishing
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-02
Phishing
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-03
Phishing
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-04
Phishing
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-05
Phishing
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-06
Phishing
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-07
Phishing
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-08
Phishing
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-09
Phishing
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-10
Phishing
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-11
Phishing
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-12
Phishing
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-13
Phishing
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-14
Phishing
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-001-15
Phishing
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-01
Business Email Compromise
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-02
Business Email Compromise
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-03
Business Email Compromise
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-04
Business Email Compromise
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-05
Business Email Compromise
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-06
Business Email Compromise
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-07
Business Email Compromise
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-08
Business Email Compromise
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-09
Business Email Compromise
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-10
Business Email Compromise
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-11
Business Email Compromise
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-12
Business Email Compromise
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-13
Business Email Compromise
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-14
Business Email Compromise
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-002-15
Business Email Compromise
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-01
Ransomware
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-02
Ransomware
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-03
Ransomware
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-04
Ransomware
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-05
Ransomware
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-06
Ransomware
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-07
Ransomware
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-08
Ransomware
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-09
Ransomware
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-10
Ransomware
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-11
Ransomware
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-12
Ransomware
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-13
Ransomware
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-14
Ransomware
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-003-15
Ransomware
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-01
Endpoint Malware
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-02
Endpoint Malware
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-03
Endpoint Malware
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-04
Endpoint Malware
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-05
Endpoint Malware
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-06
Endpoint Malware
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-07
Endpoint Malware
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-08
Endpoint Malware
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-09
Endpoint Malware
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-10
Endpoint Malware
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-11
Endpoint Malware
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-12
Endpoint Malware
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-13
Endpoint Malware
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-14
Endpoint Malware
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-004-15
Endpoint Malware
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-01
Privileged Account Compromise
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-02
Privileged Account Compromise
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-03
Privileged Account Compromise
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-04
Privileged Account Compromise
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-05
Privileged Account Compromise
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-06
Privileged Account Compromise
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-07
Privileged Account Compromise
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-08
Privileged Account Compromise
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-09
Privileged Account Compromise
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-10
Privileged Account Compromise
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-11
Privileged Account Compromise
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-12
Privileged Account Compromise
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-13
Privileged Account Compromise
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-14
Privileged Account Compromise
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-005-15
Privileged Account Compromise
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-01
Cloud IAM Abuse
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-02
Cloud IAM Abuse
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-03
Cloud IAM Abuse
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-04
Cloud IAM Abuse
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-05
Cloud IAM Abuse
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-06
Cloud IAM Abuse
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-07
Cloud IAM Abuse
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-08
Cloud IAM Abuse
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-09
Cloud IAM Abuse
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-10
Cloud IAM Abuse
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-11
Cloud IAM Abuse
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-12
Cloud IAM Abuse
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-13
Cloud IAM Abuse
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-14
Cloud IAM Abuse
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-006-15
Cloud IAM Abuse
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-01
Data Exfiltration
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-02
Data Exfiltration
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-03
Data Exfiltration
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-04
Data Exfiltration
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-05
Data Exfiltration
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-06
Data Exfiltration
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-07
Data Exfiltration
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-08
Data Exfiltration
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-09
Data Exfiltration
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-10
Data Exfiltration
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-11
Data Exfiltration
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-12
Data Exfiltration
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-13
Data Exfiltration
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-14
Data Exfiltration
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-007-15
Data Exfiltration
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-01
Vulnerability Exploitation
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-02
Vulnerability Exploitation
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-03
Vulnerability Exploitation
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-04
Vulnerability Exploitation
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-05
Vulnerability Exploitation
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-06
Vulnerability Exploitation
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-07
Vulnerability Exploitation
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-08
Vulnerability Exploitation
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-09
Vulnerability Exploitation
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-10
Vulnerability Exploitation
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-11
Vulnerability Exploitation
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-12
Vulnerability Exploitation
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-13
Vulnerability Exploitation
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-14
Vulnerability Exploitation
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-008-15
Vulnerability Exploitation
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-01
Network Intrusion
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-02
Network Intrusion
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-03
Network Intrusion
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-04
Network Intrusion
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-05
Network Intrusion
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-06
Network Intrusion
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-07
Network Intrusion
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-08
Network Intrusion
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-09
Network Intrusion
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-10
Network Intrusion
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-11
Network Intrusion
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-12
Network Intrusion
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-13
Network Intrusion
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-14
Network Intrusion
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-009-15
Network Intrusion
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-01
Suspicious Script Execution
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-02
Suspicious Script Execution
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-03
Suspicious Script Execution
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-04
Suspicious Script Execution
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-05
Suspicious Script Execution
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-06
Suspicious Script Execution
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-07
Suspicious Script Execution
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-08
Suspicious Script Execution
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-09
Suspicious Script Execution
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-10
Suspicious Script Execution
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-11
Suspicious Script Execution
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-12
Suspicious Script Execution
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-13
Suspicious Script Execution
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-14
Suspicious Script Execution
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-010-15
Suspicious Script Execution
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-01
Persistence Mechanism
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-02
Persistence Mechanism
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-03
Persistence Mechanism
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-04
Persistence Mechanism
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-05
Persistence Mechanism
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-06
Persistence Mechanism
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-07
Persistence Mechanism
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-08
Persistence Mechanism
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-09
Persistence Mechanism
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-10
Persistence Mechanism
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-11
Persistence Mechanism
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-12
Persistence Mechanism
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-13
Persistence Mechanism
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-14
Persistence Mechanism
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-011-15
Persistence Mechanism
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-01
DDoS
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-02
DDoS
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-03
DDoS
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-04
DDoS
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-05
DDoS
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-06
DDoS
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-07
DDoS
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-08
DDoS
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-09
DDoS
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-10
DDoS
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-11
DDoS
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-12
DDoS
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-13
DDoS
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-14
DDoS
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-012-15
DDoS
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-01
Insider Risk
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-02
Insider Risk
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-03
Insider Risk
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-04
Insider Risk
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-05
Insider Risk
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-06
Insider Risk
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-07
Insider Risk
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-08
Insider Risk
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-09
Insider Risk
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-10
Insider Risk
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-11
Insider Risk
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-12
Insider Risk
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-13
Insider Risk
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-14
Insider Risk
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-013-15
Insider Risk
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-01
Third-Party Alert
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-02
Third-Party Alert
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-03
Third-Party Alert
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-04
Third-Party Alert
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-05
Third-Party Alert
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-06
Third-Party Alert
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-07
Third-Party Alert
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-08
Third-Party Alert
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-09
Third-Party Alert
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-10
Third-Party Alert
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-11
Third-Party Alert
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-12
Third-Party Alert
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-13
Third-Party Alert
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-14
Third-Party Alert
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-014-15
Third-Party Alert
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-01
Connector Health Failure
Trigger and classify
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-02
Connector Health Failure
Gather source alert and raw evidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-03
Connector Health Failure
Enrich entities and indicators
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-04
Connector Health Failure
Check asset/user criticality
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-05
Connector Health Failure
Search related events
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-06
Connector Health Failure
Assess severity and confidence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-07
Connector Health Failure
Determine customer notification need
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-08
Connector Health Failure
Run safe containment recommendation
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-09
Connector Health Failure
Request approval if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-10
Connector Health Failure
Execute authorised action
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-11
Connector Health Failure
Create customer/internal tasks
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-12
Connector Health Failure
Monitor for recurrence
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-13
Connector Health Failure
Close with disposition
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-14
Connector Health Failure
Capture detection feedback
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.
PB-015-15
Connector Health Failure
Generate report/PIR if required
Inputs from case, connector, rule, tenant policy and analyst context.
Output logged to case timeline and audit trail.


Appendix K - Detailed Build User Stories and Acceptance Criteria
Story ID
Area
User Story
Acceptance Criteria
Mandatory Tests
US-001
Tenant onboarding
As an authorised user, I want tenant onboarding capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-002
RBAC and MFA
As an authorised user, I want rbac and mfa capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-003
Alert ingestion API
As an authorised user, I want alert ingestion api capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-004
Syslog collector
As an authorised user, I want syslog collector capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-005
Case management
As an authorised user, I want case management capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-006
Incident timeline
As an authorised user, I want incident timeline capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-007
Entity graph
As an authorised user, I want entity graph capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-008
Evidence locker
As an authorised user, I want evidence locker capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-009
SLA timers
As an authorised user, I want sla timers capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-010
Microsoft connector
As an authorised user, I want microsoft connector capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-011
Connector health
As an authorised user, I want connector health capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-012
Detection editor
As an authorised user, I want detection editor capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-013
Rule testing
As an authorised user, I want rule testing capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-014
False positive tuning
As an authorised user, I want false positive tuning capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-015
SOAR approval
As an authorised user, I want soar approval capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-016
Playbook execution
As an authorised user, I want playbook execution capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-017
AI alert summary
As an authorised user, I want ai alert summary capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-018
AI incident report draft
As an authorised user, I want ai incident report draft capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-019
Monthly service report
As an authorised user, I want monthly service report capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-020
Compliance evidence pack
As an authorised user, I want compliance evidence pack capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-021
Package entitlements
As an authorised user, I want package entitlements capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-022
Usage metering
As an authorised user, I want usage metering capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-023
MSSP tenant hierarchy
As an authorised user, I want mssp tenant hierarchy capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-024
Audit log search
As an authorised user, I want audit log search capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-025
Data retention
As an authorised user, I want data retention capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-026
War-room mode
As an authorised user, I want war-room mode capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-027
Threat intel enrichment
As an authorised user, I want threat intel enrichment capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-028
Vulnerability context
As an authorised user, I want vulnerability context capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-029
Customer task workflow
As an authorised user, I want customer task workflow capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.
US-030
Offboarding archive
As an authorised user, I want offboarding archive capability so that the SOC platform can deliver secure and measurable operations.
Given valid role and tenant context, when the user completes the workflow, then the system updates records, enforces permissions, logs audit events, and displays success/failure clearly.
Must include negative permission test, tenant isolation test, audit log test, and error path test.


Appendix L - Operational Reports and KPI Definitions
KPI
Definition
Segmentation / Notes
Mean Time to Triage
Time from alert creation/ingestion to first analyst triage decision.
By tenant, severity, data source, analyst shift.
Mean Time to Acknowledge
Time from customer-visible incident to customer acknowledgement or SOC acknowledgement depending SLA.
By package and severity.
Mean Time to Containment
Time from confirmed incident to approved containment action completion.
Only for incidents where containment applicable.
False Positive Rate
Percentage of alerts closed as false positive by rule/source/tenant.
Measured after onboarding tuning window.
Data Source Health
Percentage of time priority data sources are active and within lag threshold.
Critical source outage affects service review.
SLA Compliance
Incidents handled within contractual thresholds.
By severity and package.
Analyst Utilisation
Queue work, cases, investigations, service tasks, admin time.
SOC management only.
Detection Coverage
Mapped ATT&CK techniques with active rules and required data sources.
Shows limitations where data missing.
Response Action Success
Approved playbook actions completed successfully.
By connector/action/risk class.
Customer Remediation Age
Open customer tasks by age and severity.
Used in service reviews.
Evidence Freshness
Age of evidence for compliance controls.
Compliance dashboard.
Churn/Renewal Risk
Combination of usage, SLA, incidents, satisfaction, receivables.
Commercial dashboard.
Gross Margin by Tenant
Revenue less tooling, storage, analyst time, support, pro services.
Internal finance only.
AI Assistance Acceptance
AI suggestions accepted/edited/rejected/unsafe.
AI governance.
Connector Error Rate
Failed connector runs versus total runs.
Platform health and onboarding quality.

Appendix M - Final Truth Notes and Build Warnings
Building the platform is achievable with Developers and a disciplined engineering team, but SOC credibility depends on expert configuration, detection engineering, analyst operations, incident response governance, and customer trust.
The system must be positioned honestly: it reduces risk and improves detection/response; it cannot guarantee breach prevention.
Commercial packages must enforce limits, or anchor customers can destroy margin through bespoke scope creep.
AI must be designed with safety controls, evidence grounding, tenant isolation, and human approval for high-impact actions.
The first commercial release should be narrow enough to operate well, not broad enough to look impressive but fail in production.
The platform should not try to replace every SIEM/EDR/firewall. It should provide a strong SOC operating layer above them, with native capabilities where strategically valuable.
A senior cybersecurity architect and SOC operations lead should review this SRS before using it as the final source of truth for implementation.
