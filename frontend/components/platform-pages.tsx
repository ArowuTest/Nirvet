// Platform feature pages — content-driven. One PLATFORM_CONTENT map (keyed by slug) + one PlatformPage renderer, so
// the five Platform footer links each get a real, on-brand page describing an actual Nirvet capability (not a stub).
// Copy is grounded in the shipped platform: SOAR actioners, authority-to-act with four-eyes, reversible actions,
// fleet-wide guardrails, AI egress redaction, evidence chain-of-custody, and the connector ingestion seam.

import { Icon } from "@/components/icons";
import { MarketingShell, PageHero, FeatureGrid, CTABand } from "@/components/site";

type PlatformDoc = {
  label: string;
  title: string;
  highlight: string; // trailing phrase rendered in the primary colour
  sub: string;
  lead: string;
  features: { icon: string; title: string; body: string }[];
  capabilities: string[];
  cta: { title: string; sub: string };
};

export const PLATFORM_CONTENT: Record<string, PlatformDoc> = {
  "detection-response": {
    label: "Platform",
    title: "Detection &",
    highlight: "Response",
    sub: "Correlate signals across your entire data estate, surface the findings that matter, and act on them — with automation where it's safe and human approval where it counts.",
    lead: "Nirvet unifies EDR, SIEM, cloud, identity, and network telemetry into a single detection and response plane. AI models correlate weak signals into high-confidence findings, and every response action runs through a governed authority model — so analysts move from alert to contained in minutes, not hours, without ever losing control.",
    features: [
      { icon: "activity", title: "AI-assisted triage", body: "Signals are correlated across sources and scored, so analysts open a ranked queue of decisions instead of a firehose of raw alerts." },
      { icon: "target", title: "Governed response actions", body: "Isolate a host, disable an account, block a hash, revoke a session — vendor actioners for Microsoft, Okta, and CrowdStrike, with more added continuously." },
      { icon: "shield", title: "Authority to act", body: "Every action is gated by an authority policy: observe, approval-required, or automated. Business-critical assets never auto-run under any mode." },
      { icon: "log-out", title: "Reversible by design", body: "Containment actions carry a defined inverse. A single click safely lifts an isolation or restores an account — and never undoes an effect Nirvet didn't create." },
    ],
    capabilities: [
      "Four-eyes approval gates on high-consequence actions",
      "Fleet-wide actions (e.g. tenant-wide IOC blocks) are always approval-first and human-run — never auto-executed",
      "Terminal-state fail-safe: already-contained targets are attributed correctly, so a reversal can't touch a pre-existing state",
      "Full audit trail of every decision, approval, and action — exportable to your SIEM",
      "MTTR, SLA-at-risk, and containment metrics tracked per incident",
    ],
    cta: { title: "See detection & response on your own telemetry", sub: "We'll connect a test source, walk an event from alert to contained, and show the authority model in action." },
  },
  "ai-copilot": {
    label: "Platform",
    title: "AI",
    highlight: "Co-pilot",
    sub: "An analyst co-pilot that summarises investigations, suggests next steps, and drafts response actions — with governed egress and a human always in the loop.",
    lead: "The Nirvet AI co-pilot accelerates the parts of an investigation that drain analyst time: building context, summarising timelines, and proposing response actions. It runs behind an egress-redaction fence and an admin-controlled provider allowlist, so sensitive data is handled on your terms — and every suggestion is a recommendation a human confirms, never an unattended action.",
    features: [
      { icon: "target", title: "Investigation summaries", body: "Turn a sprawling alert timeline into a concise narrative — what happened, which entities are involved, and what to check next." },
      { icon: "shield", title: "Egress redaction fence", body: "Outbound prompts are redacted against a zero-config floor before they ever reach a model. Empty config never means 'send everything'." },
      { icon: "settings", title: "Admin-controlled providers", body: "You choose the LLM provider and an explicit model allowlist per tenant. Governance is a configuration record, not a code change." },
      { icon: "file-text", title: "Evaluated prompts", body: "Prompts live in a versioned registry with a hermetic evaluation harness and a CI fence — changes are tested, not shipped blind." },
    ],
    capabilities: [
      "Human-in-the-loop by default — the co-pilot proposes, an analyst decides",
      "Per-tenant data isolation carries into every AI interaction",
      "Redaction is applied at the boundary and audited",
      "Customer-approval and retention controls for AI-processed data",
      "No training on your data",
    ],
    cta: { title: "Put the co-pilot to work in a live investigation", sub: "See how summarisation and suggested actions shorten triage — with the redaction fence and provider controls switched on." },
  },
  "playbook-engine": {
    label: "Platform",
    title: "Playbook",
    highlight: "Engine",
    sub: "Encode your team's institutional knowledge into versioned, auditable playbooks — with automated steps for the routine and approval gates where human judgement matters.",
    lead: "The Nirvet playbook engine turns tribal knowledge into repeatable, reviewable response. Playbooks are versioned and auditable; steps can enrich, collect evidence, notify, and execute governed response actions. Where consequence is high, an approval gate pauses for a human — and every action the engine takes is one it also knows how to undo.",
    features: [
      { icon: "grid", title: "Versioned & auditable", body: "Every playbook and every run is versioned. You can always answer what ran, on what, decided by whom, and why." },
      { icon: "shield", title: "Approval gates", body: "Insert human checkpoints anywhere. High-risk steps require sign-off; four-eyes enforces a second approver on the most consequential." },
      { icon: "log-out", title: "Reversal built in", body: "Actions carry an inverse, so a run can be safely rolled back. Reversal only touches what the run actually changed." },
      { icon: "settings", title: "No hardcoded thresholds", body: "Authority modes, timeouts, and break-glass are admin-config policy records with seeded safe defaults — tuned without a deploy." },
    ],
    capabilities: [
      "Authority ladder per action type: observe → approval → pre-authorized → contractual-auto",
      "Break-glass and per-action timeout policies, configurable with guardrails",
      "Automated enrichment, evidence collection, and notification steps",
      "Runs are idempotent and safe to retry",
      "Every step decision is written to the audit trail",
    ],
    cta: { title: "Turn your runbooks into governed playbooks", sub: "Bring a runbook you use today — we'll model it as a Nirvet playbook with the right approval gates and reversals." },
  },
  "evidence-management": {
    label: "Platform",
    title: "Evidence",
    highlight: "Management",
    sub: "Every artifact collected during an investigation is timestamped, hashed, and stored with provenance — ready for regulatory review, legal proceedings, or internal audit.",
    lead: "Investigations are only as defensible as their evidence. Nirvet captures every artifact with a cryptographic hash, a timestamp, and full provenance metadata, then preserves the chain of custody from collection to export. Legal hold, retention, and export packaging are first-class — so when someone asks how you know, you have the record to prove it.",
    features: [
      { icon: "server", title: "Chain of custody", body: "Who collected what, when, from where, and every hand-off since — recorded immutably alongside the artifact." },
      { icon: "shield", title: "Integrity by hash", body: "Each artifact is hashed on capture. Tampering is detectable; integrity is verifiable at any later point." },
      { icon: "file-text", title: "Export packages", body: "Assemble a complete, self-describing evidence pack for auditors, regulators, or counsel — on demand." },
      { icon: "grid", title: "Legal hold & retention", body: "Place holds that survive routine retention, and enforce deletion schedules that are themselves auditable and atomic." },
    ],
    capabilities: [
      "Timestamped, hashed artifacts with provenance metadata",
      "Legal hold that overrides retention until released",
      "Retention-delete that is atomic and recorded",
      "Evidence tied to the incident, playbook run, and decisions that produced it",
      "Export aligned to regulatory and legal review needs",
    ],
    cta: { title: "See evidence you can defend", sub: "We'll walk a collected artifact from capture through hashing, custody, and a regulator-ready export pack." },
  },
  integrations: {
    label: "Platform",
    title: "",
    highlight: "Integrations",
    sub: "Connect the tools you already run — EDR, SIEM, cloud, identity, and email — through a governed connector layer with safe egress and normalised telemetry.",
    lead: "Nirvet meets your stack where it lives. A connector wizard onboards each source with a guided create-configure-test flow; ingestion mappers normalise incoming telemetry to a common schema; and response actioners reach back into your tools to contain, disable, and block. All outbound calls run through an SSRF-safe egress layer, and credentials are encrypted at rest.",
    features: [
      { icon: "plug", title: "Guided connector wizard", body: "Add a source, configure it, and test the connection before it goes live — no guesswork, clear failure reasons." },
      { icon: "share-2", title: "Normalised ingestion", body: "Mappers translate each vendor's telemetry into one schema, so detection content and investigations work across sources." },
      { icon: "target", title: "Response actioners", body: "Microsoft Defender, Entra, and M365; Okta identity; CrowdStrike EDR host containment and fleet-wide IOC blocks — with more added continuously." },
      { icon: "shield", title: "Safe by construction", body: "Outbound requests are SSRF-guarded, credentials are encrypted, and every connector action is authority-gated and audited." },
    ],
    capabilities: [
      "EDR, SIEM, cloud, identity, and email source connectors",
      "Per-tenant connector configuration and isolation",
      "Health and degraded-state visibility per integration",
      "Response coverage expanding across identity, endpoint, and network vendors",
      "Region-aware endpoints, including sovereign/GovCloud where required",
    ],
    cta: { title: "Connect your stack in an afternoon", sub: "Tell us what you run — we'll show the connector flow, the normalised telemetry, and the response actions available today." },
  },
};

export const PLATFORM_SLUGS = Object.keys(PLATFORM_CONTENT);

export function PlatformPage({ slug }: { slug: string }) {
  const doc = PLATFORM_CONTENT[slug];
  if (!doc) return null;
  return (
    <MarketingShell>
      <PageHero
        label={doc.label}
        title={<>{doc.title && <>{doc.title} </>}<span style={{ color: "var(--c-primary)" }}>{doc.highlight}</span></>}
        sub={doc.sub}
      />
      <section>
        <div className="mx-auto max-w-4xl px-6 py-14 md:px-10">
          <p className="text-[17px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{doc.lead}</p>
        </div>
      </section>
      <section>
        <div className="mx-auto max-w-7xl px-6 pb-4 md:px-10">
          <FeatureGrid items={doc.features} />
        </div>
      </section>
      <section>
        <div className="mx-auto max-w-4xl px-6 py-14 md:px-10">
          <h2 className="text-xl font-bold">What you get</h2>
          <ul className="mt-6 flex flex-col gap-3">
            {doc.capabilities.map((c) => (
              <li key={c} className="flex items-start gap-3 text-[15px]" style={{ color: "var(--c-ink-2)" }}>
                <span className="mt-0.5 shrink-0" style={{ color: "var(--c-accent)" }}><Icon name="shield" size={16} /></span>
                {c}
              </li>
            ))}
          </ul>
        </div>
      </section>
      <CTABand title={doc.cta.title} sub={doc.cta.sub} />
    </MarketingShell>
  );
}
