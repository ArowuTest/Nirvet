# SOC Platform — Build Backlog

> Clean markdown of `docs/source/06_SOC_Platform_Build_Backlog.xlsx` (source of truth = the `.xlsx`).
> Five sheets: **Backlog** (16 epics / 64 stories), **Integration Roadmap** (16), **Playbooks** (6),
> **Detection Use Cases** (10), **Dashboard** (summary).

## Dashboard summary

| Metric | Count |
|---|---|
| Total user stories | 64 |
| MVP user stories | 36 |
| V1 user stories | 20 |
| V2 user stories | 8 |
| High priority stories | 36 |
| Integration items | 16 |
| Detection use cases | 10 |
| Playbooks defined | 6 |

## Backlog — epics & stories

> Every story shares the same template. **User story:** *"As a [owner role], I need to [capability] so that the
> SOC platform can operate securely and repeatably."* **Acceptance criteria:** *"[Capability] is available in the
> relevant portal/API, is tenant-scoped, logged in audit trail, covered by tests, and documented."*
> **Dependencies:** E01–E07 → "Architecture sign-off"; E07+ → "MVP foundation". **Status:** all *Not Started*.

| Epic | Story | Capability | Owner role | Priority | Release |
|---|---|---|---|---|---|
| **E01** Tenant & Customer Management | US-001 | Create tenant | Platform Admin | High | MVP |
| E01 | US-002 | Configure service tier | Platform Admin | High | MVP |
| E01 | US-003 | Manage escalation contacts | Platform Admin | High | MVP |
| E01 | US-004 | Track onboarding status | Platform Admin | High | MVP |
| **E02** Identity, RBAC & SSO | US-005 | Role-based permissions | Security Architect | High | MVP |
| E02 | US-006 | MFA enforcement | Security Architect | High | MVP |
| E02 | US-007 | SSO support | Security Architect | High | MVP |
| E02 | US-008 | Privileged action audit | Security Architect | High | MVP |
| **E03** Ingestion & Normalisation | US-009 | Receive raw events | Backend Engineer | High | MVP |
| E03 | US-010 | Normalize to common schema | Backend Engineer | High | MVP |
| E03 | US-011 | Deduplicate events | Backend Engineer | High | MVP |
| E03 | US-012 | Create parser error queue | Backend Engineer | High | MVP |
| **E04** Alert Queue & Triage | US-013 | Filter alert queue | SOC Lead | High | MVP |
| E04 | US-014 | Assign analyst | SOC Lead | High | MVP |
| E04 | US-015 | Set severity/confidence | SOC Lead | High | MVP |
| E04 | US-016 | Convert alert to incident | SOC Lead | High | MVP |
| **E05** Incident Case Management | US-017 | Create incident case | Product Owner | High | MVP |
| E05 | US-018 | Build incident timeline | Product Owner | High | MVP |
| E05 | US-019 | Manage tasks/actions | Product Owner | High | MVP |
| E05 | US-020 | Close with report | Product Owner | High | MVP |
| **E06** Evidence & Audit Trail | US-021 | Store evidence item | Compliance Lead | High | MVP |
| E06 | US-022 | Hash evidence | Compliance Lead | High | MVP |
| E06 | US-023 | Export audit trail | Compliance Lead | High | MVP |
| E06 | US-024 | Apply retention policy | Compliance Lead | High | MVP |
| **E07** Customer Portal & Reporting | US-025 | Customer incident view | Frontend Engineer | High | MVP |
| E07 | US-026 | Monthly report generation | Frontend Engineer | High | MVP |
| E07 | US-027 | Executive dashboard | Frontend Engineer | High | MVP |
| E07 | US-028 | Customer approval workflow | Frontend Engineer | High | MVP |
| **E08** Microsoft Integrations | US-029 | M365 audit connector | Integration Engineer | High | MVP |
| E08 | US-030 | Entra sign-in connector | Integration Engineer | High | MVP |
| E08 | US-031 | Defender alert connector | Integration Engineer | High | MVP |
| E08 | US-032 | Connector health monitoring | Integration Engineer | High | MVP |
| **E09** Syslog/Webhook/API Collectors | US-033 | Syslog listener | Backend Engineer | High | MVP |
| E09 | US-034 | Webhook endpoint | Backend Engineer | High | MVP |
| E09 | US-035 | Customer API ingestion | Backend Engineer | High | MVP |
| E09 | US-036 | Source authentication | Backend Engineer | High | MVP |
| **E10** Detection Engineering Workspace | US-037 | Rule catalogue | Detection Engineer | Medium | V1 |
| E10 | US-038 | Sigma upload/validation | Detection Engineer | Medium | V1 |
| E10 | US-039 | MITRE mapping | Detection Engineer | Medium | V1 |
| E10 | US-040 | Rule testing workflow | Detection Engineer | Medium | V1 |
| **E11** Threat Intelligence Enrichment | US-041 | IOC enrichment | Threat Intel Lead | Medium | V1 |
| E11 | US-042 | TLP marking | Threat Intel Lead | Medium | V1 |
| E11 | US-043 | STIX/TAXII feed support | Threat Intel Lead | Medium | V1 |
| E11 | US-044 | Watchlist management | Threat Intel Lead | Medium | V1 |
| **E12** SOAR Playbooks & Approvals | US-045 | Playbook designer | SOC Lead | Medium | V1 |
| E12 | US-046 | Approval gate | SOC Lead | Medium | V1 |
| E12 | US-047 | Action connector run | SOC Lead | Medium | V1 |
| E12 | US-048 | Playbook audit log | SOC Lead | Medium | V1 |
| **E13** AI SOC Assistant | US-049 | Alert summarisation | AI Engineer | Medium | V1 |
| E13 | US-050 | Investigation suggestions | AI Engineer | Medium | V1 |
| E13 | US-051 | Incident report draft | AI Engineer | Medium | V1 |
| E13 | US-052 | AI guardrail logging | AI Engineer | Medium | V1 |
| **E14** Connector Marketplace | US-053 | Connector configuration UI | Integration Engineer | Medium | V1 |
| E14 | US-054 | Credential vault integration | Integration Engineer | Medium | V1 |
| E14 | US-055 | Rate-limit handling | Integration Engineer | Medium | V1 |
| E14 | US-056 | Connector SDK template | Integration Engineer | Medium | V1 |
| **E15** MSSP/White-label Mode | US-057 | Partner hierarchy | Product Owner | Medium | V2 |
| E15 | US-058 | White-label branding | Product Owner | Medium | V2 |
| E15 | US-059 | Partner billing view | Product Owner | Medium | V2 |
| E15 | US-060 | Sub-customer management | Product Owner | Medium | V2 |
| **E16** Sovereign/Dedicated Deployment | US-061 | Deployment profile | Cloud Architect | Medium | V2 |
| E16 | US-062 | Data residency controls | Cloud Architect | Medium | V2 |
| E16 | US-063 | Dedicated instance pipeline | Cloud Architect | Medium | V2 |
| E16 | US-064 | DR runbook | Cloud Architect | Medium | V2 |

## Integration roadmap

| # | Integration | Category | Phase | Direction | Data/Action scope | Auth | Notes |
|---|---|---|---|---|---|---|---|
| 1 | Microsoft 365 | Productivity/Email | MVP | Read | Audit logs, mailbox indicators, risky email activity | OAuth / Graph API | High market coverage |
| 2 | Entra ID | Identity | MVP | Read/Action | Sign-ins, users, MFA, token/session actions | OAuth / Graph API | Core identity telemetry |
| 3 | Microsoft Defender | EDR/XDR | MVP | Read/Action | Alerts, device info, isolate device where authorised | OAuth/API | Strong first EDR path |
| 4 | Syslog | Generic | MVP | Read | Firewall/router/server/appliance events | TLS/syslog certs | Broadest generic ingestion |
| 5 | Webhook/API | Generic | MVP | Read | Customer alerts/events from any source | API key/OAuth/HMAC | Flexible onboarding |
| 6 | Jira / ServiceNow | Ticketing | MVP/V1 | Read/Write | Create/update tickets, sync status | OAuth/API tokens | Enterprise workflow |
| 7 | AWS | Cloud | V1 | Read | CloudTrail, GuardDuty, IAM, security findings | IAM role/API | Cloud expansion |
| 8 | Azure | Cloud | V1 | Read | Activity logs, Defender for Cloud, security alerts | OAuth | Microsoft enterprise |
| 9 | Fortinet | Firewall | V1 | Read/Action | Firewall logs, block IP/domain where authorised | API/syslog | Common network control |
| 10 | Palo Alto | Firewall | V1 | Read/Action | Firewall/threat logs, policy block | API/syslog | Enterprise firewall |
| 11 | CrowdStrike | EDR | V1 | Read/Action | Detections, host telemetry, isolate host | OAuth/API | Premium MDR |
| 12 | SentinelOne | EDR | V1 | Read/Action | Threats, endpoint response actions | API token | Premium MDR |
| 13 | Okta | Identity | V2 | Read/Action | Identity events, session/account actions | OAuth/API | Enterprise identity |
| 14 | Cloudflare | Edge | V2 | Read/Action | WAF/DNS/access logs, blocklists | API token | Edge/cloud security |
| 15 | Zscaler | SASE | V2 | Read/Action | Web/proxy/zero-trust events | API | Large enterprise |
| 16 | Vulnerability scanners | Exposure | V1 | Read | Findings, asset criticality, remediation status | API | Exposure management |

## Playbooks

| Playbook | Initial severity | Required data | Automated evidence | Possible actions | Approval required | Owner |
|---|---|---|---|---|---|---|
| Phishing / BEC | P2 | Email logs, identity logs, user/device data | Email headers, recipient list, clicked links, mailbox rules | Quarantine email, revoke sessions, reset password | Yes for account actions | SOC Lead |
| Compromised identity | P2 | Sign-in logs, MFA, admin changes | Recent sign-ins, MFA changes, token use, mailbox activity | Revoke sessions, disable account, reset password | Yes unless pre-authorised | Tier 2 Analyst |
| Malware endpoint | P2 | EDR telemetry, process tree, hash intel | Process tree, file hash, network connections, device owner | Isolate device, kill process, quarantine file | Yes | Tier 2 Analyst |
| Ransomware suspected | P1 | EDR, file activity, identity, network | Affected assets, file rename patterns, lateral movement, backup status | Isolate endpoints, block indicators, escalate IR | Emergency policy | IR Lead |
| Cloud account compromise | P2 | Cloud audit, IAM, network, workload logs | API calls, IAM changes, resource creation | Disable key, rotate credentials, block source | Yes | Cloud Security |
| Data exfiltration suspected | P1/P2 | Network, DLP, cloud storage, file access | Volume, destination, user/entity, sensitive asset link | Block destination, disable account, legal escalation | Yes | IR Lead |

## Detection use cases

| Domain | Use case | Data sources | MITRE mapping | Default severity | Release | Notes |
|---|---|---|---|---|---|---|
| Identity | Impossible travel followed by MFA change | Entra/Okta/Google | Initial Access / Credential Access | P2 | MVP | Validate user travel and VPN exceptions |
| Identity | Repeated MFA denied prompts | Entra/Okta | Credential Access | P2 | MVP | Potential MFA fatigue |
| Email | Mailbox forwarding rule to external address | M365/Google Workspace | Collection / Exfiltration | P2 | MVP | High BEC value |
| Email | Phishing click plus risky sign-in | Email security + identity | Initial Access | P2 | MVP | Correlated detection |
| Endpoint | Encoded PowerShell command | Defender/CrowdStrike/SentinelOne | Execution | P2/P3 | V1 | Tune admin scripts |
| Endpoint | Ransomware-like file modifications | EDR / file telemetry | Impact | P1/P2 | V1 | Critical containment |
| Cloud | Admin key created for privileged user | AWS/Azure/GCP | Privilege Escalation | P2 | V1 | Monitor service accounts |
| Network | Outbound to malicious IP/domain | Firewall/DNS/proxy | Command and Control | P2/P3 | V1 | Threat intel context |
| Vulnerability | Exploited critical vulnerability exposed to internet | Scanner + firewall + threat intel | Initial Access | P1/P2 | V1 | Tie to asset criticality |
| Data | Large unusual outbound transfer from critical system | Network/cloud/storage | Exfiltration | P1/P2 | V2 | Requires baseline |
