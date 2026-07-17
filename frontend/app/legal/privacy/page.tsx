// Privacy Policy. Standard, comprehensive policy content styled with the shared Prose helpers. Directs data-subject
// and DPO enquiries to privacy@nirvet.com. Effective-date driven; reviewed periodically (noted in the body).

import type { Metadata } from "next";
import { MarketingShell, PageHero, Prose, LegalHeading, CONTACT_EMAIL } from "@/components/site";

export const metadata: Metadata = {
  title: "Privacy Policy — Nirvet",
  description: "How Nirvet collects, uses, protects, and shares personal data, and the rights you have over it.",
};

const PRIVACY_EMAIL = "privacy@nirvet.com";

export default function PrivacyPage() {
  return (
    <MarketingShell>
      <PageHero label="Legal" title="Privacy Policy" sub="How we handle personal data across our website and platform — and the rights you have over it." />
      <section>
        <div className="mx-auto max-w-4xl px-6 py-14 md:px-10">
          <p className="mb-8 text-[13px]" style={{ color: "var(--c-ink-3)" }}>Last updated: 17 July 2026</p>
          <Prose>
            <p>
              This Privacy Policy explains how Nirvet Ltd (&quot;Nirvet&quot;, &quot;we&quot;, &quot;us&quot;) collects,
              uses, discloses, and safeguards personal data when you visit our website, contact us, or use the Nirvet
              platform. We act as a data controller for personal data we collect directly, and as a data processor for
              personal data our customers process through the platform under their own agreements.
            </p>

            <LegalHeading>Data we collect</LegalHeading>
            <p>We collect only what we need to provide and improve our services:</p>
            <ul className="ml-5 list-disc space-y-1.5">
              <li><strong>Contact data</strong> — name, email, company, and the content of any message you send us through the site or by email.</li>
              <li><strong>Account data</strong> — for platform users: identity, role, and authentication metadata (we never store passwords in plain text).</li>
              <li><strong>Usage &amp; technical data</strong> — IP address, device/browser type, and audit logs of actions taken within the platform, for security and accountability.</li>
              <li><strong>Customer telemetry</strong> — security data our customers ingest is processed strictly on their behalf, under their control and their retention rules.</li>
            </ul>

            <LegalHeading>How we use it</LegalHeading>
            <p>We use personal data to respond to enquiries, provide and secure the platform, meet legal and regulatory obligations, and improve our services. We do not sell personal data, and we do not use customer telemetry to train models.</p>

            <LegalHeading>Legal bases</LegalHeading>
            <p>Where the GDPR or comparable law applies, we rely on: performance of a contract (providing the service), legitimate interests (securing and improving it), consent (where required, e.g. optional communications), and legal obligation (compliance and record-keeping).</p>

            <LegalHeading>Sharing &amp; sub-processors</LegalHeading>
            <p>We share personal data only with vetted sub-processors that support our operations (e.g. hosting and infrastructure), bound by contractual data-protection terms; when required by law or to protect rights and safety; and with your direction. A current list of sub-processors is available to customers on request.</p>

            <LegalHeading>International transfers</LegalHeading>
            <p>Where data is transferred across borders, we use appropriate safeguards such as Standard Contractual Clauses. For customers with data-residency requirements, the platform supports regional, private-cloud, on-premises, and air-gapped deployment so data can stay within your chosen jurisdiction.</p>

            <LegalHeading>Retention</LegalHeading>
            <p>We keep personal data only as long as necessary for the purposes above or as required by law. Customer telemetry is retained per the retention rules the customer configures, and deletion is enforced and auditable.</p>

            <LegalHeading>Security</LegalHeading>
            <p>Data is encrypted in transit (TLS 1.3) and at rest (AES-256). Access is authorised against policy with a full audit trail, and enterprise tenants may use customer-managed keys. We apply the same security posture to our own operations that we help customers enforce.</p>

            <LegalHeading>Your rights</LegalHeading>
            <p>Subject to applicable law, you may request access to, correction of, deletion of, or restriction of your personal data, and object to certain processing or request portability. To exercise any right, contact us at <a href={`mailto:${PRIVACY_EMAIL}`} style={{ color: "var(--c-primary)" }}>{PRIVACY_EMAIL}</a>. You also have the right to lodge a complaint with your local data-protection authority.</p>

            <LegalHeading>Changes</LegalHeading>
            <p>We review this policy periodically and will update the date above when we make material changes. Significant changes will be communicated to affected customers.</p>

            <LegalHeading>Contact</LegalHeading>
            <p>For privacy questions or to reach our data-protection contact, email <a href={`mailto:${PRIVACY_EMAIL}`} style={{ color: "var(--c-primary)" }}>{PRIVACY_EMAIL}</a>, or reach us via our <a href="/contact" style={{ color: "var(--c-primary)" }}>contact page</a>. General enquiries: <a href={`mailto:${CONTACT_EMAIL}`} style={{ color: "var(--c-primary)" }}>{CONTACT_EMAIL}</a>.</p>
          </Prose>
        </div>
      </section>
    </MarketingShell>
  );
}
