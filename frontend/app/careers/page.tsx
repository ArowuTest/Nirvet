// Careers — honest about stage. No fabricated open reqs with fake locations/salaries; instead: how we work, the
// disciplines we hire into, and a direct channel (careers@nirvet.com) to introduce yourself. Roles are framed as
// "where we typically hire" so the page stays truthful whether or not a specific seat is open today.

import type { Metadata } from "next";
import { Icon } from "@/components/icons";
import { MarketingShell, PageHero } from "@/components/site";

export const metadata: Metadata = {
  title: "Careers — Nirvet",
  description: "Build AI-native security operations with a small, senior team. Introduce yourself.",
};

const CAREERS_EMAIL = "careers@nirvet.com";

const VALUES = [
  { icon: "shield", title: "Ownership over process", body: "Small, senior team. You own problems end to end and ship them — not tickets in a queue." },
  { icon: "target", title: "Correctness is the culture", body: "We build safety-critical software. We verify claims at the source, write the failing test first, and treat a green from a check that ran nothing as worth nothing." },
  { icon: "users", title: "Remote-first, deep-work biased", body: "Async by default, few meetings, long uninterrupted stretches to do the hard thinking security work demands." },
];

const DISCIPLINES = [
  { title: "Detection Engineering", body: "Author and tune detection content; turn adversary behaviour into high-fidelity, low-noise signals." },
  { title: "Backend Engineering (Go)", body: "Build the detection, SOAR, and evidence core — RLS-isolated, test-first, safety-gated." },
  { title: "Frontend Engineering (Next.js)", body: "Craft the analyst experience: keyboard-first workflows wired to real backend contracts." },
  { title: "Security Analysts / SOC", body: "Operate the platform, hunt threats, and shape the product from the front line of incident response." },
  { title: "Solutions & Customer Engineering", body: "Onboard customers, model their runbooks as playbooks, and scope deployments across cloud and on-prem." },
];

export default function CareersPage() {
  return (
    <MarketingShell>
      <PageHero
        label="Careers"
        title={<>Build the platform that <span style={{ color: "var(--c-primary)" }}>defends the defenders</span></>}
        sub="We're a small, senior team building AI-native security operations for high-stakes environments. If governed autonomy, evidence you can defend, and correctness-as-culture sound like your kind of problem, we'd like to hear from you."
      />

      <section>
        <div className="mx-auto max-w-7xl px-6 py-14 md:px-10">
          <h2 className="text-xl font-bold">How we work</h2>
          <div className="mt-8 grid gap-6 md:grid-cols-3">
            {VALUES.map((v) => (
              <div key={v.title} className="p-7" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)", borderRadius: 24 }}>
                <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-lg" style={{ background: "rgba(14,165,233,0.1)", border: "1px solid rgba(14,165,233,0.2)", color: "var(--c-primary)" }}>
                  <Icon name={v.icon} size={20} />
                </div>
                <h3 className="text-[16px] font-bold">{v.title}</h3>
                <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{v.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section>
        <div className="mx-auto max-w-4xl px-6 pb-6 md:px-10">
          <h2 className="text-xl font-bold">Where we hire</h2>
          <p className="mt-3 text-[15px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>
            We open specific roles as the team grows. These are the disciplines we hire into — if your strengths are
            here, introduce yourself even when nothing is formally posted. Strong people create their own seat.
          </p>
          <div className="mt-8 flex flex-col gap-3">
            {DISCIPLINES.map((d) => (
              <div key={d.title} className="flex items-start gap-4 rounded-2xl p-5" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)" }}>
                <span className="mt-0.5 shrink-0" style={{ color: "var(--c-accent)" }}><Icon name="target" size={18} /></span>
                <div>
                  <h3 className="text-[15px] font-bold">{d.title}</h3>
                  <p className="mt-1 text-[13px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{d.body}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section>
        <div className="mx-auto max-w-4xl px-6 py-14 md:px-10">
          <div className="rounded-2xl p-8 text-center" style={{ background: "linear-gradient(135deg, rgba(14,165,233,0.12), rgba(6,182,212,0.06))", border: "1px solid var(--c-border)" }}>
            <h2 className="text-2xl font-extrabold tracking-tight">Introduce yourself</h2>
            <p className="mx-auto mt-3 max-w-xl text-[15px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>
              Send us what you&apos;ve built and the kind of problem you want to work on. Include a CV, a portfolio, or
              just a link to something you&apos;re proud of. We read every message.
            </p>
            <a href={`mailto:${CAREERS_EMAIL}?subject=Introducing%20myself%20to%20Nirvet`} className="mt-6 inline-flex rounded-lg px-6 py-3 text-sm font-semibold text-white" style={{ background: "var(--c-primary)" }}>
              Email {CAREERS_EMAIL}
            </a>
          </div>
        </div>
      </section>
    </MarketingShell>
  );
}
