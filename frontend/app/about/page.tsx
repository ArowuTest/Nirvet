// About — company positioning and operating principles. Deliberately free of fabricated specifics (headcount,
// funding, offices); it states what Nirvet is, who it serves, and the principles the product is actually built on.

import type { Metadata } from "next";
import { Icon } from "@/components/icons";
import { MarketingShell, PageHero, CTABand } from "@/components/site";

export const metadata: Metadata = {
  title: "About — Nirvet",
  description: "Nirvet builds AI-native security operations for enterprises and operators that cannot afford to be slow.",
};

// The name is an acronym — three pillars across the six letters.
const PILLARS = [
  { letters: "NI", title: "Network Intelligence", body: "Correlate signals across your entire network and data estate into intelligence analysts can actually act on — not raw, disconnected telemetry." },
  { letters: "RV", title: "Risk Visibility", body: "Surface true risk and posture — what matters, why, and how exposed you are — so teams focus on decisions instead of drowning in alerts." },
  { letters: "ET", title: "Event Triage", body: "Turn a flood of events into a ranked queue of decisions, with AI-assisted triage and governed, reversible response." },
];

const PRINCIPLES = [
  { icon: "shield", title: "Governed autonomy", body: "Automation should move fast without moving recklessly. Every automated action passes through an explicit authority model, and the highest-consequence actions always wait for a human." },
  { icon: "users", title: "Human-in-the-loop", body: "AI accelerates analysts; it doesn't replace their judgement. The co-pilot proposes and summarises — people decide, and the decision is always recorded." },
  { icon: "server", title: "Evidence-first", body: "If you can't prove what happened, it didn't happen defensibly. Provenance, hashing, and chain of custody are built into the platform, not bolted on afterwards." },
  { icon: "grid", title: "Sovereign by design", body: "Data residency isn't a checkbox. Nirvet deploys in cloud, private cloud, on-prem, and air-gapped environments so control stays where it belongs — with you." },
];

export default function AboutPage() {
  return (
    <MarketingShell>
      <PageHero
        label="About"
        title={<>Security operations at <span style={{ color: "var(--c-primary)" }}>machine speed</span>, with human control</>}
        sub="Nirvet is an AI-native security operations platform for organisations and service providers that operate in high-stakes, highly-regulated environments."
      />

      {/* What the name means — the NIRVET acronym */}
      <section style={{ background: "var(--c-surface)", borderBottom: "1px solid var(--c-border)" }}>
        <div className="mx-auto max-w-7xl px-6 py-16 md:px-10">
          <div className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-widest" style={{ color: "var(--c-primary)" }}>What the name means</div>
          <h2 className="mt-4 text-2xl font-extrabold tracking-tight md:text-3xl">
            NIRVET — <span style={{ color: "var(--c-primary)" }}>Network Intelligence, Risk Visibility &amp; Event Triage</span>
          </h2>
          <p className="mt-4 max-w-2xl text-[16px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>
            The name is a promise about what the platform does. Three capabilities, one plane: see your network clearly,
            understand your real risk, and act on the events that matter.
          </p>
          <div className="mt-10 grid gap-6 md:grid-cols-3">
            {PILLARS.map((p) => (
              <div key={p.title} className="p-7" style={{ background: "var(--c-bg)", border: "1px solid var(--c-border)", borderRadius: 24 }}>
                <div className="flex h-12 w-12 items-center justify-center rounded-xl text-lg font-extrabold" style={{ background: "rgba(14,165,233,0.12)", border: "1px solid rgba(14,165,233,0.25)", color: "var(--c-primary)" }}>
                  {p.letters}
                </div>
                <h3 className="mt-4 text-[17px] font-bold">{p.title}</h3>
                <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{p.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section>
        <div className="mx-auto max-w-4xl px-6 py-14 md:px-10">
          <h2 className="text-xl font-bold">Why we built Nirvet</h2>
          <div className="mt-5 flex flex-col gap-5 text-[16px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>
            <p>
              Security teams are drowning. Alerts pile up faster than analysts can triage them, context is scattered
              across a dozen consoles, and the moment a real incident lands, the clock that matters most — time to
              contain — is the one that's hardest to beat. The industry's answer has too often been more dashboards,
              or unattended automation that trades control for speed.
            </p>
            <p>
              We think that's a false choice. Nirvet consolidates detection, investigation, and response into one
              plane, uses AI to do the heavy lifting of correlation and summarisation, and wraps every response action
              in a governance model that a regulator, an auditor, or your own board would recognise as sound. You get
              the speed of automation and the accountability of human oversight — not one at the expense of the other.
            </p>
            <p>
              Nirvet is built to serve both ends of the market: enterprises that run their own SOC and want a better
              platform, and managed security service providers who operate detection and response on behalf of many
              customers at once. The same governance, isolation, and evidence guarantees hold either way.
            </p>
          </div>
        </div>
      </section>

      <section>
        <div className="mx-auto max-w-7xl px-6 pb-6 md:px-10">
          <h2 className="text-xl font-bold">What we believe</h2>
          <div className="mt-8 grid gap-6 md:grid-cols-2">
            {PRINCIPLES.map((p) => (
              <div key={p.title} className="p-7" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)", borderRadius: 24 }}>
                <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-lg" style={{ background: "rgba(14,165,233,0.1)", border: "1px solid rgba(14,165,233,0.2)", color: "var(--c-primary)" }}>
                  <Icon name={p.icon} size={20} />
                </div>
                <h3 className="text-[16px] font-bold">{p.title}</h3>
                <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{p.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section>
        <div className="mx-auto max-w-4xl px-6 py-14 md:px-10">
          <h2 className="text-xl font-bold">Who we serve</h2>
          <p className="mt-5 text-[16px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>
            Financial services, healthcare, government and public sector, and critical infrastructure — organisations
            where a security failure carries regulatory, safety, or national consequences. Nirvet is designed to meet
            the obligations these sectors carry, from DORA and PCI-DSS to HIPAA, NIS2, and sovereign classification
            handling, and to give operators the multi-tenant control they need to serve many of them at once.
          </p>
        </div>
      </section>

      <CTABand title="Want to see how we'd fit your environment?" sub="Talk to our team about the platform, managed coverage, or a proof of concept." />
    </MarketingShell>
  );
}
