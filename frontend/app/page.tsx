// Nirvet marketing landing — ported faithfully from the approved Landing-Page-v2 mockup (brand, copy, sections,
// and the hero dashboard-preview). Static server component; the only live destination is /login (Sign in). All
// colours come from the globals.css design tokens. Sections: nav · hero · why · platform-vs-managed · deployment
// · by-industry · security & trust · CTA band · footer.

import Link from "next/link";
import { Icon, NirvetMark } from "@/components/icons";

const NAV_LINKS = [
  { label: "Platform", href: "#why" },
  { label: "Deployment", href: "#deployment" },
  { label: "By Industry", href: "#industry" },
  { label: "Security", href: "#security" },
];

const WHY = [
  { icon: "activity", title: "AI-assisted triage", body: "Nirvet's AI models correlate signals across your data estate, surface high-confidence findings, and suggest response actions — so analysts focus on decisions, not data wrangling." },
  { icon: "grid", title: "Single pane of glass", body: "Unify EDR, SIEM, cloud logs, and network telemetry in one workspace. Investigation timelines, entity graphs, and evidence live together — no more pivoting between consoles." },
  { icon: "target", title: "Playbook automation", body: "Encode your team's institutional knowledge into versioned, auditable playbooks. Automated steps handle routine tasks; approval gates enforce human oversight where it matters." },
  { icon: "users", title: "MSSP multi-tenancy", body: "Manage dozens of customer environments from a single platform. Granular RBAC, per-tenant data isolation, and consolidated billing give service providers complete operational control." },
  { icon: "server", title: "Evidence & chain of custody", body: "Every artifact collected during an investigation is timestamped, hashed, and stored with provenance metadata — ready for regulatory review, legal proceedings, or internal audit." },
  { icon: "shield", title: "Analyst experience first", body: "Designed for the analysts who live in the product. Keyboard-first workflows, smart search, and context-aware AI suggestions reduce cognitive load during high-pressure incidents." },
];

const DEPLOY = [
  { title: "SaaS Cloud", body: "Hosted on Nirvet-managed infrastructure. Ideal for organisations that want rapid deployment with minimal operational overhead. Data encrypted in transit and at rest." },
  { title: "Private Cloud / On-Prem", body: "Deploy inside your VPC, data centre, or air-gapped environment. Full data-residency control with no data leaving your perimeter. Supports HSM key management." },
  { title: "Hybrid / Federated", body: "Orchestrate detection across cloud and on-prem estates. Centralised correlation plane with distributed collection agents — no telemetry hairpin to the cloud required." },
];

const INDUSTRY = [
  { label: "Financial Services", title: "Banks, Fintechs & Payment Processors", body: "Support for DORA, PCI-DSS, and SWIFT requirements. Pre-built detection content for fraud, account takeover, and insider threat. Automated regulatory evidence packages on demand." },
  { label: "Healthcare & Life Sciences", title: "Hospitals, Health Networks & Pharma", body: "Built to support HIPAA, NIS2, and NHS DSPT obligations. OT/IoMT device monitoring, ransomware detection for clinical environments, and breach-notification workflow templates." },
  { label: "Government & Public Sector", title: "Agencies, Ministries & CNI Operators", body: "On-premises and classified-network deployment. Supply-chain monitoring, nation-state threat-intel integration, and support for sovereign classification handling." },
  { label: "Manufacturing & Critical Infrastructure", title: "Industrial, Energy & OT Environments", body: "Passive OT monitoring with no disruption to production networks. IT/OT convergence visibility, ICS protocol decoding, and playbooks designed for operational safety constraints." },
];

const TRUST = [
  { title: "Encryption by default", body: "All data encrypted in transit (TLS 1.3) and at rest (AES-256). Customer-managed key (CMK) support for enterprise tenants.", note: "Key management via BYOK or HSM integration" },
  { title: "Compliance readiness", body: "Built to support NIS2, DORA, HIPAA, ISO 27001, and PCI-DSS. Compliance mapping and reporting tooling included in every tier.", note: "Certification status disclosed upon request under NDA" },
  { title: "Zero-trust access controls", body: "Every API call and UI action is authorised against policy. Role- and attribute-based access, with full audit trail exported to your SIEM.", note: "Supports SAML 2.0, OIDC, and SCIM provisioning" },
  { title: "Availability & resiliency", body: "Multi-region redundancy for SaaS deployments. Graceful degradation modes for on-prem. SLA commitments documented in your service agreement.", note: "SLA terms negotiated per contract — not published without evidence" },
  { title: "Vulnerability disclosure", body: "Responsible disclosure policy publicly available. Annual third-party penetration testing. Critical findings remediated on a risk-tiered schedule.", note: "Pentest scope and methodology shared with enterprise customers" },
  { title: "Incident response for you", body: "In a platform security incident, we apply our own response process — with notification timelines and remediation steps defined in your agreement.", note: "Breach notification timelines align to NIS2 / GDPR requirements" },
];

const card = { background: "var(--c-surface)", border: "1px solid var(--c-border)", borderRadius: 24 } as const;

export default function Home() {
  return (
    <div style={{ background: "var(--c-bg)", color: "var(--c-ink)" }}>
      {/* NAV */}
      <nav className="fixed inset-x-0 top-0 z-50 h-16 border-b backdrop-blur" style={{ background: "rgba(5,13,26,0.85)", borderColor: "var(--c-border)" }}>
        <div className="mx-auto flex h-full max-w-7xl items-center gap-10 px-6 md:px-10">
          <Link href="/" className="flex items-center gap-2.5">
            <NirvetMark size={32} />
            <span className="text-lg font-extrabold tracking-tight">NIR<span style={{ color: "var(--c-primary)" }}>VET</span></span>
          </Link>
          <div className="hidden flex-1 items-center gap-7 md:flex">
            {NAV_LINKS.map((l) => (
              <a key={l.href} href={l.href} className="text-sm font-medium transition hover:text-white" style={{ color: "var(--c-ink-2)" }}>{l.label}</a>
            ))}
          </div>
          <div className="ml-auto flex items-center gap-3">
            <Link href="/login" className="rounded-lg px-4 py-2 text-sm font-semibold transition" style={{ color: "var(--c-ink-2)", border: "1px solid var(--c-border)" }}>Sign In</Link>
            <a href="#cta" className="rounded-lg px-5 py-2 text-sm font-semibold text-white transition" style={{ background: "var(--c-primary)" }}>Request Demo</a>
          </div>
        </div>
      </nav>

      {/* HERO */}
      <header className="relative overflow-hidden pt-16">
        <div className="pointer-events-none absolute inset-0" style={{ background: "radial-gradient(ellipse 70% 60% at 60% 40%, rgba(14,165,233,0.07) 0%, transparent 70%), radial-gradient(ellipse 50% 40% at 80% 80%, rgba(6,182,212,0.05) 0%, transparent 60%)" }} />
        <div className="pointer-events-none absolute inset-0" style={{ backgroundImage: "linear-gradient(rgba(14,165,233,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(14,165,233,0.04) 1px, transparent 1px)", backgroundSize: "64px 64px" }} />
        <div className="relative mx-auto grid max-w-7xl items-center gap-16 px-6 py-20 md:grid-cols-2 md:px-10">
          <div>
            <span className="mb-6 inline-flex items-center gap-2 rounded-full px-3.5 py-1.5 text-xs font-semibold uppercase tracking-wider" style={{ background: "rgba(14,165,233,0.1)", border: "1px solid rgba(14,165,233,0.25)", color: "var(--c-primary)" }}>
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: "var(--c-accent)" }} />
              AI-Native SOC Platform
            </span>
            <h1 className="text-4xl font-extrabold leading-[1.1] tracking-tight md:text-5xl lg:text-6xl">
              Security operations at{" "}
              <span style={{ background: "linear-gradient(135deg, var(--c-primary), var(--c-accent))", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>machine speed</span>
            </h1>
            <p className="mt-6 max-w-lg text-lg leading-relaxed" style={{ color: "var(--c-ink-2)" }}>
              Nirvet consolidates detection, investigation, and response across your hybrid environment — with AI co-pilots that surface what matters and accelerate every step of the workflow.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-4">
              <a href="#cta" className="rounded-lg px-7 py-3.5 text-base font-semibold text-white transition" style={{ background: "var(--c-primary)" }}>Request a Demo</a>
              <a href="#why" className="rounded-lg px-7 py-3.5 text-base font-semibold transition" style={{ color: "var(--c-primary)", border: "1px solid var(--c-primary)" }}>Explore Platform</a>
            </div>
            <div className="mt-12 flex flex-wrap items-center gap-6">
              {["On-prem & cloud deployment", "MSSP multi-tenant", "BYO data lake"].map((t) => (
                <span key={t} className="flex items-center gap-2 text-[13px]" style={{ color: "var(--c-ink-3)" }}>
                  <span className="h-1.5 w-1.5 rounded-full" style={{ background: "var(--c-accent)" }} />{t}
                </span>
              ))}
            </div>
          </div>
          <HeroDashboard />
        </div>
      </header>

      {/* WHY */}
      <Section id="why" label="Why Nirvet" title={<>Built for the complexities <span style={{ color: "var(--c-ink-2)" }}>modern SOCs face</span></>} sub="Security teams are drowning in alerts, context-switching between tools, and losing time to manual triage. Nirvet changes that equation.">
        <div className="mt-14 grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {WHY.map((w) => (
            <div key={w.title} className="p-8 transition hover:border-[color:var(--c-border-strong)]" style={card}>
              <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-lg" style={{ background: "rgba(14,165,233,0.1)", border: "1px solid rgba(14,165,233,0.2)", color: "var(--c-primary)" }}>
                <Icon name={w.icon} size={22} />
              </div>
              <h3 className="text-[17px] font-bold">{w.title}</h3>
              <p className="mt-2.5 text-sm leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{w.body}</p>
            </div>
          ))}
        </div>
      </Section>

      <Divider />

      {/* PLATFORM vs MANAGED */}
      <Section id="engagement" label="Deployment Model" title={<>Platform or managed — <span style={{ color: "var(--c-ink-2)" }}>you decide the engagement</span></>} sub="Whether you want to operate Nirvet yourself or have our team manage the SOC function, we fit how your organisation works.">
        <div className="mt-14 grid gap-6 md:grid-cols-2">
          <CompareCard tone="platform" tag="Self-Operated Platform" title="Nirvet Platform" desc="Your team, your environment. Deploy the Nirvet platform inside your infrastructure and operate it with your analysts." items={["Full control of data residency & sovereignty", "BYO data lake, SIEM, or use built-in", "Annual platform licence with tiered ingestion", "Custom playbook development & integration support", "Suitable for enterprises with mature in-house SOC teams"]} cta="View Platform Specs" />
          <CompareCard tone="managed" featured tag="Fully Managed Service" title="Nirvet MSSP" desc="Let the Nirvet team operate the platform on your behalf. 24×7 analyst coverage, threat hunting, and incident response included." items={["Dedicated analyst team & escalation path", "Proactive threat hunting included", "Defined response SLAs in your service agreement", "Customer portal with real-time incident visibility", "Suitable for organisations scaling without adding headcount"]} cta="Talk to a Solution Architect" />
        </div>
      </Section>

      <Divider />

      {/* DEPLOYMENT */}
      <Section id="deployment" label="Deployment" title={<>Your infrastructure, <span style={{ color: "var(--c-ink-2)" }}>your compliance posture</span></>} sub="Nirvet is designed to meet you where your data lives — whether that's cloud-native, air-gapped, or somewhere in between.">
        <div className="mt-14 grid gap-5 md:grid-cols-3">
          {DEPLOY.map((d) => (
            <div key={d.title} className="p-7" style={card}>
              <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-lg" style={{ background: "rgba(14,165,233,0.1)", color: "var(--c-primary)" }}>
                <Icon name="box" size={20} />
              </div>
              <h3 className="text-base font-bold">{d.title}</h3>
              <p className="mt-2 text-[13px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{d.body}</p>
            </div>
          ))}
        </div>
      </Section>

      <Divider />

      {/* BY INDUSTRY */}
      <Section id="industry" label="By Industry" title={<>Designed for high-stakes <span style={{ color: "var(--c-ink-2)" }}>security environments</span></>} sub="Different industries face different regulatory obligations and threat profiles. Nirvet adapts to each.">
        <div className="mt-14 grid gap-6 md:grid-cols-2">
          {INDUSTRY.map((i) => (
            <div key={i.label} className="grid grid-cols-[auto_1fr] items-start gap-5 p-8" style={card}>
              <div className="flex h-13 w-13 items-center justify-center rounded-2xl" style={{ background: "rgba(14,165,233,0.1)", border: "1px solid rgba(14,165,233,0.2)", color: "var(--c-primary)", height: 52, width: 52 }}>
                <Icon name="shield" size={24} />
              </div>
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider" style={{ color: "var(--c-ink-3)" }}>{i.label}</div>
                <h3 className="mt-1.5 text-[17px] font-bold">{i.title}</h3>
                <p className="mt-2.5 text-[13px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{i.body}</p>
              </div>
            </div>
          ))}
        </div>
      </Section>

      <Divider />

      {/* SECURITY & TRUST */}
      <Section id="security" label="Security & Trust" title={<>How we protect the <span style={{ color: "var(--c-ink-2)" }}>platform you trust us with</span></>} sub="We hold ourselves to the same standard we help you enforce. Our security posture is built in, not bolted on.">
        <div className="mt-14 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {TRUST.map((t) => (
            <div key={t.title} className="p-7 text-center" style={card}>
              <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl" style={{ background: "rgba(14,165,233,0.1)", color: "var(--c-primary)" }}>
                <Icon name="shield" size={24} />
              </div>
              <h3 className="text-base font-bold">{t.title}</h3>
              <p className="mt-2 text-[13px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{t.body}</p>
              <p className="mt-2.5 text-[11px] italic" style={{ color: "var(--c-ink-3)" }}>{t.note}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* CTA BAND */}
      <section id="cta" className="border-y" style={{ background: "linear-gradient(135deg, rgba(14,165,233,0.12), rgba(6,182,212,0.06))", borderColor: "var(--c-border)" }}>
        <div className="mx-auto grid max-w-7xl items-center gap-12 px-6 py-20 md:grid-cols-[1fr_auto] md:px-10">
          <div>
            <h2 className="text-3xl font-extrabold tracking-tight md:text-4xl">Ready to see Nirvet in your environment?</h2>
            <p className="mt-3 max-w-lg text-base" style={{ color: "var(--c-ink-2)" }}>Talk to a solution architect. We'll walk through your use case, answer technical questions, and scope a proof of concept.</p>
          </div>
          <div className="flex flex-col items-start gap-3 md:items-end">
            <Link href="/login" className="rounded-lg px-7 py-3.5 text-base font-semibold text-white" style={{ background: "var(--c-primary)" }}>Sign in to the console</Link>
            <a href="mailto:hello@nirvet.io?subject=Nirvet%20technical%20overview" className="rounded-lg px-7 py-3.5 text-base font-semibold" style={{ color: "var(--c-primary)", border: "1px solid var(--c-primary)" }}>Download Technical Overview</a>
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer style={{ background: "var(--c-surface)", borderTop: "1px solid var(--c-border)" }}>
        <div className="mx-auto max-w-7xl px-6 py-12 md:px-10">
          <div className="grid gap-10 md:grid-cols-[2fr_1fr_1fr_1fr]">
            <div>
              <div className="flex items-center gap-2.5">
                <NirvetMark size={30} />
                <span className="text-lg font-extrabold tracking-tight">NIR<span style={{ color: "var(--c-primary)" }}>VET</span></span>
              </div>
              <p className="mt-3 max-w-xs text-[13px]" style={{ color: "var(--c-ink-2)" }}>AI-powered cyber operations for enterprises that cannot afford to be slow.</p>
            </div>
            <FooterCol title="Platform" links={["Detection & Response", "AI Co-pilot", "Playbook Engine", "Evidence Management", "Integrations"]} />
            <FooterCol title="Company" links={["About", "Careers", "Blog", "Contact"]} />
            <FooterCol title="Legal" links={["Privacy Policy", "Terms of Service", "Security Disclosure", "Cookie Preferences"]} />
          </div>
          <div className="mt-10 flex flex-col items-center justify-between gap-3 border-t pt-6 text-[12px] sm:flex-row" style={{ borderColor: "var(--c-border)", color: "var(--c-ink-3)" }}>
            <span>© 2025 Nirvet Ltd. All rights reserved.</span>
            <span className="flex gap-5">
              <span>Privacy</span><span>Terms</span><span>Security</span>
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}

function Section({ id, label, title, sub, children }: { id?: string; label: string; title: React.ReactNode; sub: string; children: React.ReactNode }) {
  return (
    <section id={id}>
      <div className="mx-auto max-w-7xl px-6 py-24 md:px-10">
        <div className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-widest" style={{ color: "var(--c-primary)" }}>{label}</div>
        <h2 className="mt-4 max-w-3xl text-3xl font-extrabold leading-tight tracking-tight md:text-4xl">{title}</h2>
        <p className="mt-5 max-w-xl text-[17px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{sub}</p>
        {children}
      </div>
    </section>
  );
}

function Divider() {
  return <hr className="mx-auto max-w-7xl" style={{ border: "none", borderTop: "1px solid var(--c-border)" }} />;
}

function CompareCard({ tone, featured, tag, title, desc, items, cta }: { tone: "platform" | "managed"; featured?: boolean; tag: string; title: string; desc: string; items: string[]; cta: string }) {
  return (
    <div className="p-9" style={{ ...card, ...(featured ? { borderColor: "var(--c-primary)", boxShadow: "0 0 32px rgba(14,165,233,0.12)" } : {}) }}>
      <span className="inline-block rounded-full px-3 py-1 text-[11px] font-bold uppercase tracking-wider" style={tone === "platform" ? { background: "rgba(14,165,233,0.12)", color: "var(--c-primary)", border: "1px solid rgba(14,165,233,0.3)" } : { background: "rgba(6,182,212,0.1)", color: "var(--c-accent)", border: "1px solid rgba(6,182,212,0.3)" }}>{tag}</span>
      <h3 className="mt-4 text-[22px] font-bold">{title}</h3>
      <p className="mt-2.5 text-sm leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{desc}</p>
      <ul className="mt-6 flex flex-col gap-2.5">
        {items.map((it) => (
          <li key={it} className="flex items-start gap-2.5 text-sm" style={{ color: "var(--c-ink-2)" }}>
            <span className="mt-0.5 shrink-0" style={{ color: "var(--c-accent)" }}><Icon name="shield" size={15} /></span>{it}
          </li>
        ))}
      </ul>
      <Link href="/login" className="mt-7 inline-flex rounded-lg px-5 py-2.5 text-sm font-semibold transition" style={featured ? { background: "var(--c-primary)", color: "#fff" } : { color: "var(--c-primary)", border: "1px solid var(--c-primary)" }}>{cta}</Link>
    </div>
  );
}

function FooterCol({ title, links }: { title: string; links: string[] }) {
  return (
    <div>
      <div className="text-[13px] font-semibold" style={{ color: "var(--c-ink)" }}>{title}</div>
      <ul className="mt-3 space-y-2">
        {links.map((l) => (
          <li key={l} className="text-[13px]" style={{ color: "var(--c-ink-3)" }}>{l}</li>
        ))}
      </ul>
    </div>
  );
}

// HeroDashboard — the mockup's product-preview frame (illustrative, static). Mirrors the SOC dashboard layout so
// the hero shows the real product shape; numbers are demonstrative, not live.
function HeroDashboard() {
  const stats = [
    { label: "Open Incidents", value: "14", change: "▲ 3 new today", tone: "var(--c-warn)" },
    { label: "Avg. MTTR", value: "47m", change: "▼ 12% vs last week", tone: "var(--c-ok)" },
    { label: "SLA at Risk", value: "2", change: "⏱ Breach in <2h", tone: "var(--c-danger)" },
    { label: "Integrations", value: "12/13", change: "1 degraded", tone: "var(--c-ink-3)" },
  ];
  const incidents = [
    { sev: "var(--c-danger)", title: "Lateral movement — Prod DC", t: "01:42:08" },
    { sev: "var(--c-warn)", title: "Exfil attempt — S3 bucket #7", t: "03:14:55" },
    { sev: "var(--c-primary)", title: "Brute-force — VPN gateway", t: "05:01:20" },
    { sev: "var(--c-ok)", title: "Policy violation — USB mount", t: "12:44:00" },
  ];
  const steps = [
    { label: "Alert triage & enrichment", state: "done" },
    { label: "Evidence collection", state: "done" },
    { label: "Containment action", state: "approve" },
    { label: "Customer notification", state: "pend" },
    { label: "Post-incident report", state: "pend" },
  ];
  return (
    <div className="overflow-hidden rounded-3xl" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border-strong)", boxShadow: "0 24px 64px rgba(0,0,0,0.6), 0 0 80px rgba(14,165,233,0.08)" }}>
      <div className="flex items-center gap-2 px-4 py-3" style={{ background: "var(--c-surface-2)", borderBottom: "1px solid var(--c-border)" }}>
        <span className="h-2.5 w-2.5 rounded-full" style={{ background: "#ef4444" }} />
        <span className="h-2.5 w-2.5 rounded-full" style={{ background: "#f59e0b" }} />
        <span className="h-2.5 w-2.5 rounded-full" style={{ background: "#10b981" }} />
        <span className="ml-2 flex-1 rounded px-3 py-1 font-mono text-[11px]" style={{ background: "rgba(14,165,233,0.05)", border: "1px solid var(--c-border)", color: "var(--c-ink-3)" }}>soc.nirvet.io / dashboard</span>
      </div>
      <div className="p-5">
        <div className="mb-4 flex items-center justify-between">
          <span className="flex items-center gap-2 rounded px-2.5 py-1.5 text-[12px] font-medium" style={{ background: "rgba(14,165,233,0.08)", border: "1px solid var(--c-border)" }}>
            Tenant: Acme Financial ▾
          </span>
          <span className="flex items-center gap-1.5 text-[11px]" style={{ color: "var(--c-ink-3)" }}>
            <span className="h-2 w-2 rounded-full" style={{ background: "#10b981", boxShadow: "0 0 6px rgba(16,185,129,0.6)" }} />All systems operational
          </span>
        </div>
        <div className="mb-4 grid grid-cols-4 gap-2.5">
          {stats.map((s) => (
            <div key={s.label} className="rounded-lg p-3" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
              <div className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>{s.label}</div>
              <div className="mt-1 text-xl font-bold">{s.value}</div>
              <div className="mt-0.5 text-[10px]" style={{ color: s.tone }}>{s.change}</div>
            </div>
          ))}
        </div>
        <div className="grid grid-cols-2 gap-2.5">
          <div className="rounded-lg p-3" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
            <div className="mb-2.5 flex justify-between text-[11px] font-semibold" style={{ color: "var(--c-ink-2)" }}>Active Incidents <span style={{ color: "var(--c-primary)" }}>View all →</span></div>
            {incidents.map((i) => (
              <div key={i.title} className="flex items-center gap-2 py-1.5 text-[11px]" style={{ borderBottom: "1px solid rgba(14,165,233,0.06)" }}>
                <span className="h-1.5 w-1.5 rounded-sm" style={{ background: i.sev }} />
                <span className="flex-1" style={{ color: "var(--c-ink-2)" }}>{i.title}</span>
                <span className="font-mono text-[10px]" style={{ color: "var(--c-ink-3)" }}>{i.t}</span>
              </div>
            ))}
          </div>
          <div className="rounded-lg p-3" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
            <div className="mb-2.5 flex justify-between text-[11px] font-semibold" style={{ color: "var(--c-ink-2)" }}>Playbook: Lateral Movement v2.4 <span style={{ color: "var(--c-primary)" }}>37%</span></div>
            {steps.map((st) => (
              <div key={st.label} className="flex items-center gap-2 py-1.5 text-[11px]">
                <span className="flex h-5 w-5 items-center justify-center rounded-full text-[9px]" style={st.state === "done" ? { background: "rgba(16,185,129,0.15)", color: "#10b981" } : st.state === "approve" ? { background: "rgba(14,165,233,0.15)", color: "var(--c-primary)" } : { background: "rgba(100,116,139,0.15)", color: "var(--c-ink-3)" }}>
                  {st.state === "done" ? "✓" : st.state === "approve" ? "!" : "•"}
                </span>
                <span className="flex-1" style={{ color: "var(--c-ink-2)" }}>{st.label}</span>
                {st.state === "approve" && <span className="rounded-full px-1.5 py-0.5 text-[9px]" style={{ border: "1px solid rgba(245,158,11,0.4)", color: "var(--c-warn)", background: "rgba(245,158,11,0.08)" }}>Approval needed</span>}
                {st.state === "done" && <span className="rounded-full px-1.5 py-0.5 text-[9px]" style={{ border: "1px solid rgba(16,185,129,0.4)", color: "#10b981", background: "rgba(16,185,129,0.08)" }}>Done</span>}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
