// Security Disclosure — coordinated vulnerability disclosure policy. Matches the platform's public commitment to a
// responsible-disclosure process. Real scope, safe-harbor language, reporting channel (security@nirvet.com), and our
// response commitments. Deliberately concrete so a good-faith researcher knows exactly how to engage.

import type { Metadata } from "next";
import { Icon } from "@/components/icons";
import { MarketingShell, PageHero, Prose, LegalHeading } from "@/components/site";

export const metadata: Metadata = {
  title: "Security Disclosure — Nirvet",
  description: "How to responsibly report a security vulnerability to Nirvet, our scope, and our commitments to researchers.",
};

const SECURITY_EMAIL = "security@nirvet.com";

export default function SecurityDisclosurePage() {
  return (
    <MarketingShell>
      <PageHero label="Legal" title="Security Disclosure" sub="We welcome reports from security researchers. This policy explains how to report a vulnerability, what's in scope, and what you can expect from us." />
      <section>
        <div className="mx-auto max-w-4xl px-6 py-14 md:px-10">
          <div className="mb-8 flex flex-col gap-3 rounded-2xl p-6 sm:flex-row sm:items-center sm:justify-between" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)" }}>
            <div className="flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-lg" style={{ background: "rgba(14,165,233,0.1)", color: "var(--c-primary)" }}><Icon name="shield" size={20} /></span>
              <div>
                <div className="text-[13px] font-semibold" style={{ color: "var(--c-ink)" }}>Report a vulnerability</div>
                <div className="text-[13px]" style={{ color: "var(--c-ink-2)" }}>Encrypted email preferred. PGP key available on request.</div>
              </div>
            </div>
            <a href={`mailto:${SECURITY_EMAIL}?subject=Security%20vulnerability%20report`} className="rounded-lg px-5 py-2.5 text-sm font-semibold text-white" style={{ background: "var(--c-primary)" }}>Email {SECURITY_EMAIL}</a>
          </div>
          <p className="mb-8 text-[13px]" style={{ color: "var(--c-ink-3)" }}>Last updated: 17 July 2026</p>
          <Prose>
            <p>Nirvet takes the security of our platform and our customers seriously. If you believe you have found a security vulnerability, we want to hear from you and will work with you to understand and resolve it quickly.</p>

            <LegalHeading>How to report</LegalHeading>
            <p>Email <a href={`mailto:${SECURITY_EMAIL}`} style={{ color: "var(--c-primary)" }}>{SECURITY_EMAIL}</a> with enough detail for us to reproduce the issue: affected component or URL, a description of the vulnerability and its impact, and step-by-step reproduction (including any proof-of-concept). Please do not include real customer data in your report.</p>

            <LegalHeading>Safe harbor</LegalHeading>
            <p>We will not pursue or support legal action against researchers who, in good faith, discover and report vulnerabilities in accordance with this policy. Act in good faith, avoid privacy violations and service disruption, and give us a reasonable time to remediate before any public disclosure, and we will treat your research as authorised.</p>

            <LegalHeading>Guidelines</LegalHeading>
            <ul className="ml-5 list-disc space-y-1.5">
              <li>Only test against accounts and data you own or are explicitly authorised to test.</li>
              <li>Do not access, modify, or exfiltrate data that is not yours.</li>
              <li>Do not run denial-of-service tests, spam, or social-engineering against our staff or customers.</li>
              <li>Do not publicly disclose a vulnerability until we have confirmed it is resolved and agreed on timing.</li>
              <li>Stop and report immediately if you encounter customer data.</li>
            </ul>

            <LegalHeading>In scope</LegalHeading>
            <p>The Nirvet platform, its APIs, and this website. Vulnerabilities such as authentication or authorisation flaws, injection, cross-tenant data exposure, SSRF, and sensitive-data handling issues are of particular interest.</p>

            <LegalHeading>Out of scope</LegalHeading>
            <ul className="ml-5 list-disc space-y-1.5">
              <li>Findings from automated scanners without a demonstrated, exploitable impact.</li>
              <li>Reports of missing best-practice headers or configurations with no proven security impact.</li>
              <li>Social engineering, physical attacks, and denial-of-service.</li>
              <li>Vulnerabilities in third-party services we do not control.</li>
            </ul>

            <LegalHeading>Our commitments</LegalHeading>
            <ul className="ml-5 list-disc space-y-1.5">
              <li>We aim to acknowledge your report within two business days.</li>
              <li>We will keep you informed as we validate and remediate.</li>
              <li>We remediate confirmed findings on a risk-tiered schedule, prioritising critical issues.</li>
              <li>With your permission, we are happy to credit your contribution once the issue is resolved.</li>
            </ul>

            <p>We also engage independent third parties for annual penetration testing; scope and methodology are shared with enterprise customers under NDA.</p>
          </Prose>
        </div>
      </section>
    </MarketingShell>
  );
}
