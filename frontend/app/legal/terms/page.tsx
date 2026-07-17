// Terms of Service. Standard SaaS terms styled with the shared Prose helpers. Points contract-level questions to
// legal@nirvet.com and defers commercial specifics (SLAs, pricing) to each customer's signed order form.

import type { Metadata } from "next";
import { MarketingShell, PageHero, Prose, LegalHeading } from "@/components/site";

export const metadata: Metadata = {
  title: "Terms of Service — Nirvet",
  description: "The terms governing use of the Nirvet website and platform.",
};

const LEGAL_EMAIL = "legal@nirvet.com";

export default function TermsPage() {
  return (
    <MarketingShell>
      <PageHero label="Legal" title="Terms of Service" sub="The terms that govern your use of the Nirvet website and platform." />
      <section>
        <div className="mx-auto max-w-4xl px-6 py-14 md:px-10">
          <p className="mb-8 text-[13px]" style={{ color: "var(--c-ink-3)" }}>Last updated: 17 July 2026</p>
          <Prose>
            <p>
              These Terms of Service (&quot;Terms&quot;) govern access to and use of the Nirvet website and platform
              provided by Nirvet Ltd (&quot;Nirvet&quot;). By accessing the site or using the platform, you agree to
              these Terms. Where you have signed a separate master agreement or order form with Nirvet, that agreement
              governs and prevails over these Terms to the extent of any conflict.
            </p>

            <LegalHeading>Use of the service</LegalHeading>
            <p>We grant you a limited, non-exclusive, non-transferable right to access and use the platform for your internal security operations, subject to these Terms and your agreement. You may not resell, reverse-engineer, or use the platform to build a competing product, except as permitted by law.</p>

            <LegalHeading>Accounts &amp; security</LegalHeading>
            <p>You are responsible for maintaining the confidentiality of credentials, for enabling appropriate access controls and multi-factor authentication, and for all activity under your accounts. Notify us promptly of any suspected unauthorised access.</p>

            <LegalHeading>Acceptable use</LegalHeading>
            <p>You agree not to use the platform unlawfully; to disrupt or compromise its integrity, security, or availability; to access data you are not authorised to access; or to use it to violate the rights of others. You are responsible for ensuring your use of response actions (e.g. containment) complies with your own policies and obligations.</p>

            <LegalHeading>Customer data</LegalHeading>
            <p>You retain all rights to the data you ingest or generate. You grant us the limited rights necessary to operate the platform and provide the service. We process customer data as a processor under your instructions and our data-protection terms. See our <a href="/legal/privacy" style={{ color: "var(--c-primary)" }}>Privacy Policy</a>.</p>

            <LegalHeading>Intellectual property</LegalHeading>
            <p>The platform, its software, and all related intellectual property remain the property of Nirvet and its licensors. These Terms do not transfer any ownership to you beyond the access rights expressly granted.</p>

            <LegalHeading>Service levels &amp; support</LegalHeading>
            <p>Availability commitments, support tiers, and response SLAs are defined in your service agreement or order form and are not published here without evidence. Where no such agreement exists, the service is provided on an as-available basis.</p>

            <LegalHeading>Disclaimers</LegalHeading>
            <p>Security tooling reduces risk but cannot guarantee prevention or detection of every threat. Except as expressly stated in a signed agreement, the platform is provided &quot;as is&quot; without warranties of any kind, to the maximum extent permitted by law.</p>

            <LegalHeading>Limitation of liability</LegalHeading>
            <p>To the maximum extent permitted by law, neither party is liable for indirect, incidental, or consequential damages. Nirvet&apos;s aggregate liability is limited as set out in your signed agreement. Nothing in these Terms limits liability that cannot be limited by law.</p>

            <LegalHeading>Termination</LegalHeading>
            <p>You may stop using the service at any time. We may suspend or terminate access for material breach of these Terms or as set out in your agreement. On termination, rights to access the platform cease; data handling on exit follows your agreement and our Privacy Policy.</p>

            <LegalHeading>Changes</LegalHeading>
            <p>We may update these Terms from time to time. Material changes will be communicated to customers, and the date above will be updated. Continued use after changes take effect constitutes acceptance.</p>

            <LegalHeading>Governing law &amp; contact</LegalHeading>
            <p>These Terms are governed by the law specified in your agreement, or otherwise by the law of the jurisdiction in which Nirvet Ltd is established. For questions about these Terms, contact <a href={`mailto:${LEGAL_EMAIL}`} style={{ color: "var(--c-primary)" }}>{LEGAL_EMAIL}</a>.</p>
          </Prose>
        </div>
      </section>
    </MarketingShell>
  );
}
