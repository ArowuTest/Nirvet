// Contact — public enquiry page. Left: direct channels (general, sales, security, press) with real addresses so the
// page is useful even without the form. Right: the enquiry form (client component; composes an email to
// contact@nirvet.com). Wrapped in the shared MarketingShell so nav + footer match the rest of the site.

import type { Metadata } from "next";
import { Icon } from "@/components/icons";
import { MarketingShell, PageHero, CONTACT_EMAIL } from "@/components/site";
import { ContactForm } from "./contact-form";

export const metadata: Metadata = {
  title: "Contact — Nirvet",
  description: "Talk to the Nirvet team about the platform, managed SOC, partnerships, or support.",
};

const CHANNELS = [
  { icon: "bell", title: "General enquiries", desc: "Questions about the platform, pricing, or a proof of concept.", value: CONTACT_EMAIL, href: `mailto:${CONTACT_EMAIL}` },
  { icon: "activity", title: "Sales & demos", desc: "Speak to a solution architect and scope a deployment.", value: "sales@nirvet.com", href: "mailto:sales@nirvet.com" },
  { icon: "shield", title: "Security & disclosure", desc: "Report a vulnerability or ask about our security posture.", value: "security@nirvet.com", href: "/legal/security-disclosure" },
  { icon: "users", title: "Partnerships", desc: "MSSP, technology, and channel partnership enquiries.", value: "partners@nirvet.com", href: "mailto:partners@nirvet.com" },
];

export default function ContactPage() {
  return (
    <MarketingShell>
      <PageHero
        label="Contact"
        title={<>Talk to the team behind <span style={{ color: "var(--c-primary)" }}>Nirvet</span></>}
        sub="Whether you're scoping a deployment, evaluating managed SOC coverage, or reporting a security issue — we'll route you to the right people. Most enquiries get a reply within one business day."
      />

      <section>
        <div className="mx-auto grid max-w-7xl gap-10 px-6 py-16 md:grid-cols-[0.9fr_1.1fr] md:px-10">
          {/* Channels */}
          <div className="flex flex-col gap-4">
            <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: "var(--c-ink-3)" }}>Direct channels</h2>
            {CHANNELS.map((c) => (
              <a key={c.title} href={c.href} className="group flex items-start gap-4 rounded-2xl p-5 transition hover:border-[color:var(--c-border-strong)]" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)" }}>
                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg" style={{ background: "rgba(14,165,233,0.1)", border: "1px solid rgba(14,165,233,0.2)", color: "var(--c-primary)" }}>
                  <Icon name={c.icon} size={20} />
                </div>
                <div>
                  <h3 className="text-[15px] font-bold">{c.title}</h3>
                  <p className="mt-1 text-[13px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{c.desc}</p>
                  <span className="mt-1.5 inline-block text-[13px] font-semibold transition group-hover:underline" style={{ color: "var(--c-primary)" }}>{c.value}</span>
                </div>
              </a>
            ))}
            <div className="mt-2 rounded-2xl p-5" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
              <h3 className="text-[13px] font-semibold" style={{ color: "var(--c-ink)" }}>Existing customer?</h3>
              <p className="mt-1 text-[13px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>
                Sign in to the console to raise a ticket, view incidents, or reach your assigned analyst team.
              </p>
              <a href="/login" className="mt-3 inline-flex text-[13px] font-semibold" style={{ color: "var(--c-primary)" }}>Sign in to the console →</a>
            </div>
          </div>

          {/* Form */}
          <div>
            <h2 className="mb-4 text-sm font-semibold uppercase tracking-widest" style={{ color: "var(--c-ink-3)" }}>Send us a message</h2>
            <ContactForm />
          </div>
        </div>
      </section>
    </MarketingShell>
  );
}
