// Cookie Preferences. Honest by construction: the app sets only strictly-necessary cookies (the httpOnly session
// cookie per ADR-0007 plus a CSRF token) — no analytics, advertising, or cross-site tracking. So rather than render
// a fake consent toggle that controls nothing, we show the real cookie categories and their true state. Essential is
// "always on" because the console cannot function without it; optional categories are honestly "none set".

import type { Metadata } from "next";
import { Icon } from "@/components/icons";
import { MarketingShell, PageHero, Prose, LegalHeading, CONTACT_EMAIL } from "@/components/site";

export const metadata: Metadata = {
  title: "Cookie Preferences — Nirvet",
  description: "The cookies Nirvet uses. We set only strictly-necessary cookies — no tracking or advertising cookies.",
};

const CATEGORIES = [
  {
    title: "Strictly necessary",
    state: "Always on",
    on: true,
    body: "Required for the platform to work. This includes the secure, httpOnly session cookie that keeps you signed in and a CSRF-protection token. These cannot be switched off because the console will not function without them.",
  },
  {
    title: "Analytics & performance",
    state: "None set",
    on: false,
    body: "We do not currently set analytics or performance cookies on this site. If that changes, this is where you'll be able to control them, and we'll ask for consent before enabling any.",
  },
  {
    title: "Advertising & tracking",
    state: "Never",
    on: false,
    body: "We do not use advertising or cross-site tracking cookies, and we have no plans to. We don't sell your data or share it with ad networks.",
  },
];

export default function CookiesPage() {
  return (
    <MarketingShell>
      <PageHero label="Legal" title="Cookie Preferences" sub="We keep this simple: Nirvet sets only the cookies strictly necessary to run the platform. No tracking, no advertising." />
      <section>
        <div className="mx-auto max-w-4xl px-6 py-14 md:px-10">
          <p className="mb-8 text-[13px]" style={{ color: "var(--c-ink-3)" }}>Last updated: 17 July 2026</p>

          <div className="flex flex-col gap-4">
            {CATEGORIES.map((c) => (
              <div key={c.title} className="rounded-2xl p-6" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)" }}>
                <div className="flex items-center justify-between gap-4">
                  <h3 className="text-[15px] font-bold">{c.title}</h3>
                  <span
                    className="inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[11px] font-semibold uppercase tracking-wider"
                    style={c.on
                      ? { background: "rgba(16,185,129,0.12)", color: "var(--c-ok)", border: "1px solid rgba(16,185,129,0.3)" }
                      : { background: "var(--c-surface-2)", color: "var(--c-ink-3)", border: "1px solid var(--c-border)" }}
                  >
                    {c.on && <Icon name="shield" size={12} />}{c.state}
                  </span>
                </div>
                <p className="mt-2 text-[13px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{c.body}</p>
              </div>
            ))}
          </div>

          <div className="mt-10">
            <Prose>
              <LegalHeading>Controlling cookies in your browser</LegalHeading>
              <p>Because we set only strictly-necessary cookies, there are no optional preferences to configure here today. You can still clear or block cookies through your browser settings — note that blocking the session cookie will prevent you from signing in to the console.</p>

              <LegalHeading>Changes</LegalHeading>
              <p>If we ever introduce optional cookies, we will update this page, add the relevant controls, and request your consent before setting them.</p>

              <LegalHeading>Questions</LegalHeading>
              <p>See our <a href="/legal/privacy" style={{ color: "var(--c-primary)" }}>Privacy Policy</a> for how we handle personal data, or email <a href={`mailto:${CONTACT_EMAIL}`} style={{ color: "var(--c-primary)" }}>{CONTACT_EMAIL}</a>.</p>
            </Prose>
          </div>
        </div>
      </section>
    </MarketingShell>
  );
}
