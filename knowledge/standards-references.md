# Standards & references

The platform aligns to widely used security-operations and cyber-risk references. These **guide** taxonomy,
reporting, evidence, control coverage, detection language, intelligence exchange, and operating-model decisions —
they are **not** copied in as rigid constraints.

| Reference | Use in the platform | Link |
|---|---|---|
| **NIST CSF 2.0** | Govern/Identify/Protect/Detect/Respond/Recover outcome mapping; board & regulator reporting; cyber-risk maturity views. | https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final |
| **NIST SP 800-61r3** | Incident-handling lifecycle: triage, containment, eradication, recovery, lessons learned. | https://csrc.nist.gov/pubs/sp/800/61/r3/final |
| **MITRE ATT&CK** (Enterprise) | Tactic/technique mapping, detection coverage, threat-hunting library, case-timeline enrichment. | https://attack.mitre.org/ |
| **OCSF** | Vendor-neutral event normalization strategy (events, entities, activities, categories, extensions). | https://ocsf.io/ |
| **Sigma** | Portable detection-rule authoring format; detection-as-code governance. | https://sigmahq.io/ |
| **STIX/TAXII 2.1** | Threat-intelligence objects, indicators, sightings, and exchange mechanism. | https://www.oasis-open.org/standard/taxii-version-2-1/ |
| **CIS Controls v8.1** | Baseline customer control mapping, audit readiness, managed-service evidence packs. | https://www.cisecurity.org/controls/v8-1 |
| **FIRST TLP 2.0** | Information-sharing classification for intelligence and incident communications. | https://www.first.org/tlp/ |
| **Zero Trust** | Identity-centric, least-privilege, assume-breach design posture across the platform. | (NIST SP 800-207) |

## ⚠️ Important caveat on NIST SP 800-61

The concise suite docs (01–05) cite **SP 800-61 Revision 3** as the incident-response reference. The SRS
front-matter notes that **Revision 2 is archived/withdrawn by NIST**, so *"final implementation should verify the
current successor guidance."* **Action:** before finalizing IR workflows, a senior cybersecurity architect should
confirm the current authoritative NIST IR guidance rather than relying on any single cited revision.

## Standing validation note (from the SRS)

The SRS is a comprehensive **draft**. It states it requires final validation by a **senior cybersecurity
architect, SOC operations lead, cloud security architect, privacy/regulatory counsel, and target-client
representatives** before being used as the final source of truth for implementation. Coding agents accelerate the
build; expert cyber review, secure configuration, detection tuning, and operational validation are required
before commercial launch.
