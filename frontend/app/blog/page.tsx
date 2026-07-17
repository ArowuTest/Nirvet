// Blog — honest empty state. No real posts exist yet, so we do NOT fabricate published articles with fake authors or
// dates. Instead we present the topics we're actively writing about (drawn from what the platform genuinely does) as
// "upcoming", clearly labelled, plus a subscribe channel. Truthful, and still a substantive page.

import type { Metadata } from "next";
import { Icon } from "@/components/icons";
import { MarketingShell, PageHero, CONTACT_EMAIL } from "@/components/site";

export const metadata: Metadata = {
  title: "Blog — Nirvet",
  description: "Field notes on AI-native security operations: governed autonomy, reversible response, and evidence you can defend.",
};

const TOPICS = [
  { icon: "shield", tag: "Response", title: "Authority to act: how to automate response without losing control", body: "The authority ladder — observe, approval, pre-authorized, contractual-auto — and why business-critical assets should never auto-run." },
  { icon: "log-out", tag: "Engineering", title: "Reversible by design: undoing a containment action safely", body: "Terminal-state fail-safe attribution, and why a reversal must only ever touch the effect your own run created." },
  { icon: "target", tag: "AI", title: "Redaction fences and the zero-config floor", body: "Why an empty AI-egress policy must mean 'redact everything', never 'send everything' — and how we enforce it at the boundary." },
  { icon: "grid", tag: "Response", title: "Fleet-wide actions deserve a different gate", body: "Breadth is its own risk axis. Why tenant-wide IOC blocks are always approval-first and human-run, independent of reversibility." },
  { icon: "server", tag: "Evidence", title: "Evidence you can defend: chain of custody in practice", body: "Hashing on capture, provenance metadata, legal hold vs retention, and building a regulator-ready export pack." },
  { icon: "users", tag: "Operations", title: "Running detection & response for many tenants at once", body: "Per-tenant isolation, consolidated operations, and the guardrails that make multi-tenant SOC work safe." },
];

export default function BlogPage() {
  return (
    <MarketingShell>
      <PageHero
        label="Blog"
        title={<>Field notes on <span style={{ color: "var(--c-primary)" }}>AI-native security operations</span></>}
        sub="Practical writing on governed autonomy, reversible response, evidence, and the engineering behind safe automation. Our first posts are on the way."
      />

      <section>
        <div className="mx-auto max-w-7xl px-6 py-14 md:px-10">
          <div className="mb-8 inline-flex items-center gap-2 rounded-full px-3.5 py-1.5 text-xs font-semibold uppercase tracking-wider" style={{ background: "rgba(14,165,233,0.1)", border: "1px solid rgba(14,165,233,0.25)", color: "var(--c-primary)" }}>
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: "var(--c-accent)" }} />
            Coming soon — topics we&apos;re writing about
          </div>
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {TOPICS.map((t) => (
              <div key={t.title} className="flex flex-col p-6" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)", borderRadius: 24 }}>
                <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-lg" style={{ background: "rgba(14,165,233,0.1)", border: "1px solid rgba(14,165,233,0.2)", color: "var(--c-primary)" }}>
                  <Icon name={t.icon} size={20} />
                </div>
                <span className="text-[11px] font-semibold uppercase tracking-wider" style={{ color: "var(--c-ink-3)" }}>{t.tag}</span>
                <h3 className="mt-1.5 text-[15px] font-bold leading-snug">{t.title}</h3>
                <p className="mt-2 text-[13px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{t.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section>
        <div className="mx-auto max-w-4xl px-6 pb-16 md:px-10">
          <div className="rounded-2xl p-8 text-center" style={{ background: "linear-gradient(135deg, rgba(14,165,233,0.12), rgba(6,182,212,0.06))", border: "1px solid var(--c-border)" }}>
            <h2 className="text-2xl font-extrabold tracking-tight">Get the first posts</h2>
            <p className="mx-auto mt-3 max-w-lg text-[15px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>
              We&apos;ll email you when we publish. No newsletter spam — just the writing.
            </p>
            <a href={`mailto:${CONTACT_EMAIL}?subject=Subscribe%20me%20to%20the%20Nirvet%20blog`} className="mt-6 inline-flex rounded-lg px-6 py-3 text-sm font-semibold text-white" style={{ background: "var(--c-primary)" }}>
              Notify me at {CONTACT_EMAIL}
            </a>
          </div>
        </div>
      </section>
    </MarketingShell>
  );
}
