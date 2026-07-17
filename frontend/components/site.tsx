// Shared public-site chrome — the ONE source of truth for the marketing nav + footer so the landing page and every
// content page (Platform, Company, Legal, Contact) stay visually and structurally identical. Static server component;
// all colours come from globals.css tokens. Footer links resolve to real routes under app/ — no dead links.

import Link from "next/link";
import { Icon, NirvetMark } from "@/components/icons";
import { SiteNav } from "@/components/site-nav";

export { SiteNav };

export const CONTACT_EMAIL = "contact@nirvet.com";

// Footer columns — the single authoritative map. Landing footer + every page footer render from this.
const FOOTER_COLS: { title: string; links: { label: string; href: string }[] }[] = [
  {
    title: "Platform",
    links: [
      { label: "Detection & Response", href: "/platform/detection-response" },
      { label: "AI Co-pilot", href: "/platform/ai-copilot" },
      { label: "Playbook Engine", href: "/platform/playbook-engine" },
      { label: "Evidence Management", href: "/platform/evidence-management" },
      { label: "Integrations", href: "/platform/integrations" },
    ],
  },
  {
    title: "Company",
    links: [
      { label: "About", href: "/about" },
      { label: "Careers", href: "/careers" },
      { label: "Blog", href: "/blog" },
      { label: "Contact", href: "/contact" },
    ],
  },
  {
    title: "Legal",
    links: [
      { label: "Privacy Policy", href: "/legal/privacy" },
      { label: "Terms of Service", href: "/legal/terms" },
      { label: "Security Disclosure", href: "/legal/security-disclosure" },
      { label: "Cookie Preferences", href: "/legal/cookies" },
    ],
  },
];

const card = { background: "var(--c-surface)", border: "1px solid var(--c-border)", borderRadius: 24 } as const;

export function SiteFooter() {
  return (
    <footer style={{ background: "var(--c-surface)", borderTop: "1px solid var(--c-border)" }}>
      <div className="mx-auto max-w-7xl px-6 py-12 md:px-10">
        <div className="grid gap-10 md:grid-cols-[2fr_1fr_1fr_1fr]">
          <div>
            <Link href="/" className="flex items-center gap-2.5">
              <NirvetMark size={30} />
              <span className="text-lg font-extrabold tracking-tight">NIR<span style={{ color: "var(--c-primary)" }}>VET</span></span>
            </Link>
            <p className="mt-3 max-w-xs text-[13px]" style={{ color: "var(--c-ink-2)" }}>AI-powered cyber operations for enterprises that cannot afford to be slow.</p>
            <p className="mt-2 max-w-xs text-[11px]" style={{ color: "var(--c-ink-3)" }}>Network Intelligence · Risk Visibility · Event Triage</p>
            <a href={`mailto:${CONTACT_EMAIL}`} className="mt-4 inline-flex items-center gap-2 text-[13px] font-medium transition hover:text-white" style={{ color: "var(--c-ink-2)" }}>
              <Icon name="bell" size={14} />{CONTACT_EMAIL}
            </a>
          </div>
          {FOOTER_COLS.map((col) => (
            <div key={col.title}>
              <div className="text-[13px] font-semibold" style={{ color: "var(--c-ink)" }}>{col.title}</div>
              <ul className="mt-3 space-y-2">
                {col.links.map((l) => (
                  <li key={l.label}>
                    <Link href={l.href} className="text-[13px] transition hover:text-white" style={{ color: "var(--c-ink-3)" }}>{l.label}</Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="mt-10 flex flex-col items-center justify-between gap-3 border-t pt-6 text-[12px] sm:flex-row" style={{ borderColor: "var(--c-border)", color: "var(--c-ink-3)" }}>
          <span>© {new Date().getFullYear()} Nirvet Ltd. All rights reserved.</span>
          <span className="flex gap-5">
            <Link href="/legal/privacy" className="transition hover:text-white" style={{ color: "var(--c-ink-3)" }}>Privacy</Link>
            <Link href="/legal/terms" className="transition hover:text-white" style={{ color: "var(--c-ink-3)" }}>Terms</Link>
            <Link href="/legal/security-disclosure" className="transition hover:text-white" style={{ color: "var(--c-ink-3)" }}>Security</Link>
          </span>
        </div>
      </div>
    </footer>
  );
}

// MarketingShell — nav + page body (offset for the fixed nav) + footer. Every content page wraps its content here.
export function MarketingShell({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ background: "var(--c-bg)", color: "var(--c-ink)", minHeight: "100vh" }}>
      <SiteNav />
      <main className="pt-16">{children}</main>
      <SiteFooter />
    </div>
  );
}

// PageHero — the standard header band for a content page (eyebrow label · title · optional sub).
export function PageHero({ label, title, sub }: { label: string; title: React.ReactNode; sub?: string }) {
  return (
    <header className="relative overflow-hidden border-b" style={{ borderColor: "var(--c-border)" }}>
      <div className="pointer-events-none absolute inset-0" style={{ background: "radial-gradient(ellipse 60% 60% at 70% 20%, rgba(14,165,233,0.08) 0%, transparent 70%)" }} />
      <div className="pointer-events-none absolute inset-0" style={{ backgroundImage: "linear-gradient(rgba(14,165,233,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(14,165,233,0.04) 1px, transparent 1px)", backgroundSize: "64px 64px" }} />
      <div className="relative mx-auto max-w-4xl px-6 py-20 md:px-10">
        <div className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-widest" style={{ color: "var(--c-primary)" }}>{label}</div>
        <h1 className="mt-4 text-3xl font-extrabold leading-[1.15] tracking-tight md:text-5xl">{title}</h1>
        {sub && <p className="mt-6 max-w-2xl text-lg leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{sub}</p>}
      </div>
    </header>
  );
}

export function ContentSection({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <section className={className}>
      <div className="mx-auto max-w-4xl px-6 py-16 md:px-10">{children}</div>
    </section>
  );
}

export const featureCard = card;

// FeatureGrid — icon/title/body cards, used on Platform pages.
export function FeatureGrid({ items }: { items: { icon: string; title: string; body: string }[] }) {
  return (
    <div className="grid gap-6 md:grid-cols-2">
      {items.map((f) => (
        <div key={f.title} className="p-7" style={card}>
          <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-lg" style={{ background: "rgba(14,165,233,0.1)", border: "1px solid rgba(14,165,233,0.2)", color: "var(--c-primary)" }}>
            <Icon name={f.icon} size={20} />
          </div>
          <h3 className="text-[16px] font-bold">{f.title}</h3>
          <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{f.body}</p>
        </div>
      ))}
    </div>
  );
}

// CTABand — the standard "talk to us" closer for content pages.
export function CTABand({ title, sub }: { title: string; sub: string }) {
  return (
    <section className="border-y" style={{ background: "linear-gradient(135deg, rgba(14,165,233,0.12), rgba(6,182,212,0.06))", borderColor: "var(--c-border)" }}>
      <div className="mx-auto grid max-w-7xl items-center gap-8 px-6 py-16 md:grid-cols-[1fr_auto] md:px-10">
        <div>
          <h2 className="text-2xl font-extrabold tracking-tight md:text-3xl">{title}</h2>
          <p className="mt-3 max-w-xl text-base" style={{ color: "var(--c-ink-2)" }}>{sub}</p>
        </div>
        <div className="flex flex-col items-start gap-3 md:items-end">
          <Link href="/contact" className="rounded-lg px-7 py-3.5 text-base font-semibold text-white" style={{ background: "var(--c-primary)" }}>Request a Demo</Link>
          <a href={`mailto:${CONTACT_EMAIL}`} className="rounded-lg px-7 py-3.5 text-base font-semibold" style={{ color: "var(--c-primary)", border: "1px solid var(--c-primary)" }}>Email {CONTACT_EMAIL}</a>
        </div>
      </div>
    </section>
  );
}

// Prose — legal / long-form document body. h2 = section heading, p/li = body. Kept token-styled, readable measure.
export function Prose({ children }: { children: React.ReactNode }) {
  return <div className="prose-nirvet flex flex-col gap-5 text-[15px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{children}</div>;
}

export function LegalHeading({ children }: { children: React.ReactNode }) {
  return <h2 className="mt-6 text-lg font-bold" style={{ color: "var(--c-ink)" }}>{children}</h2>;
}
