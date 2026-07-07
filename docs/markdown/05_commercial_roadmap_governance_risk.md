# SOC Platform — Commercial Packaging, Implementation Roadmap, Governance & Risk

> Clean markdown of `docs/source/05_Commercial_Roadmap_Governance_and_Risk.docx` (source of truth = the `.docx`/`.pdf`).

## 1. Commercial positioning

Sell the platform as a **flexible security operations platform** that can be packaged as SOCaaS, MDR, Managed
XDR, sovereign SOC, enterprise private SOC or white-label MSSP service. This avoids dependency on one market,
one country or one vendor ecosystem.

## 2. Package design

| Package | Buyer | Value proposition | Included modules |
|---|---|---|---|
| Essential Monitor | SMEs, small public agencies | Affordable monitored security with clear monthly reporting. | Tenant portal, alert queue, M365/Defender/syslog, monthly report. |
| Standard SOCaaS | Mid-market firms and MDAs | 24/7 monitoring and structured escalation without internal SOC build. | Case management, SLAs, identity/endpoint/firewall logs, quarterly review. |
| Advanced MDR | Regulated entities | Threat intel, EDR/XDR, playbooks, compliance evidence and response coordination. | Detection catalogue, SOAR, AI investigation, compliance pack. |
| Critical Infrastructure | Banks, telcos, utilities, high-risk government | Priority monitoring, custom detections, senior escalation and board reporting. | Custom detection, IR retainer, executive dashboard, dedicated service reviews. |
| Enterprise Private SOC | Large enterprise | Own SOC platform with optional managed service. | Dedicated tenant/instance, admin, analyst workbench, integrations. |
| Sovereign SOC | Country/regulator/public-sector cluster | Local data residency and sector-level security operations. | Sovereign hosting, compliance templates, central oversight dashboard. |
| White-label MSSP | MSPs/MSSPs | Rapidly launch managed security services under partner brand. | Partner portal, sub-tenancy, branded reports, reseller billing. |

## 3. Entitlements and commercial controls

| Commercial dimension | Why it matters | Contractual control |
|---|---|---|
| Assets/users | Drives monitoring volume and analyst workload. | Per-tier asset/user limits and overage pricing. |
| Log volume | Major cost driver for storage, compute and SIEM tooling. | GB/day or events/month entitlement and step-up pricing. |
| Integrations | Complex integrations increase support and maintenance. | Included connector count by tier, custom connectors as professional services. |
| Retention | Storage and compliance cost driver. | Retention duration by tier; extended retention as add-on. |
| IR support | High-value but expensive specialist capacity. | Included retainer hours by tier; day rates for excess. |
| Custom reporting | Can destroy margin if uncontrolled. | Standard reports included; bespoke packs chargeable. |
| Authority-to-act | Increases liability and operational risk. | Explicit approval matrix and limitation of liability. |

## 4. Implementation roadmap

| Phase | Timeline | Product scope | Commercial milestone |
|---|---|---|---|
| Phase 0: Design and mobilisation | Weeks 0–6 | Requirements, architecture, data model, initial backlog, security baseline, vendor decisions. | Design sign-off and build team mobilisation. |
| Phase 1: MVP build | Months 2–4 | Tenant/admin portals, ingestion, alert queue, case management, basic reports, Microsoft/syslog/webhook. | Demo to pilot customers/investors. |
| Phase 2: SOCaaS v1 | Months 5–8 | Production tenancy, SLAs, analyst workbench, connector health, compliance evidence, customer portal. | First paying pilots and go-live. |
| Phase 3: MDR/XDR expansion | Months 9–15 | EDR, firewall, cloud, threat intel, detection engineering, SOAR approvals, monthly reports. | Revenue scale and regulated-sector sales. |
| Phase 4: AI SOC | Months 12–20 | AI investigation, timeline, detection tuning assistant, executive reporting and human-in-the-loop automation. | Differentiated managed service positioning. |
| Phase 5: Sovereign/Enterprise/White-label scale | Months 18–36 | Dedicated deployments, country packs, MSP hierarchy, regulator/sector dashboards. | Regional expansion and enterprise deals. |

## 5. Governance model

| Forum | Cadence | Purpose | Attendees |
|---|---|---|---|
| Product steering | Monthly | Roadmap, priorities, customer feedback and commercial packaging. | Founder, product, SOC director, engineering lead, commercial lead. |
| Security architecture board | Fortnightly during build, monthly after launch | Approve architecture changes, data flows, integrations and security controls. | Cyber architect, DevSecOps, platform lead, data/privacy. |
| Detection review board | Weekly | Approve new/changed detections, tuning and false-positive strategy. | Detection engineer, SOC manager, T2/T3 analysts. |
| Major incident review | As needed / after P1/P2 | Review response quality, communications, lessons learned and liability. | SOC director, IR lead, customer success, legal/compliance. |
| Customer service review | Monthly/quarterly | Review KPIs, incidents, recommendations and renewal health. | Customer success, SOC lead, customer stakeholders. |

## 6. Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| Trying to build everything from scratch | Delayed launch and weak feature depth. | Build native SOC layer; integrate established tools; prioritize connectors in phases. |
| Weak cyber expert input during build | Wrong workflows, poor detections and unsafe automation. | Involve cyber architect, detection engineer and SOC lead from design stage. |
| Log cost overrun | Margin erosion. | Tiered log volume limits, overage pricing, hot/warm/cold storage and contract controls. |
| False positives overwhelm analysts | Service quality failure. | Baseline tuning, detection QA, noisy rule suppression and analyst feedback loop. |
| Unsafe autonomous response | Customer outage/liability. | Human approval, authority-to-act matrix, dry-run and audit logs. |
| Tenant data leakage | Critical trust and regulatory failure. | Tenant isolation tests, data access controls and independent security audit. |
| Procurement delays | Cash flow strain. | Blend anchor deals with private-sector pipeline and phased hiring. |
| Talent scarcity | Inability to operate 24/7 effectively. | Analyst academy, clear career path, certification funding and managed rota. |

## 7. Due diligence checklist

| Area | Questions to answer before build/launch |
|---|---|
| Regulatory | Which countries/industries are in scope? What licensing, data residency and breach notification obligations apply? |
| Commercial | Which packages launch first? What are hard asset/log/retention limits? What is the minimum viable price? |
| Technology | Which capabilities are native versus integrated? What SIEM/log store approach is chosen? |
| Operations | What is the initial coverage model? Who owns P1/P2 response? What is authority-to-act? |
| Security | How will the platform itself be protected, audited, monitored and recovered? |
| Delivery | Who reviews code from coding agents? What is the definition of done? What test evidence is required? |

## 8. Ghana sovereign SOCaaS reference wrapper

Ghana-hosted SOCaaS for public-sector, regulated and CII clients. The platform should remain broader than this
use case, but the Ghana proposition is a strong example of how the same core product can be packaged for a local

## Reference standards and sources

NIST CSF 2.0 · NIST SP 800-61r3 · MITRE ATT&CK · OCSF · Sigma · OASIS STIX/TAXII · CIS Controls v8.1 · FIRST TLP 2.0
(see [standards-references](../../knowledge/standards-references.md)).
