"use client";

// Contact form — honest by design. There is no public contact-ingest backend endpoint, so rather than pretend to
// POST (a form that shows "sent" but goes nowhere would be misleading), submit composes a pre-filled email to
// contact@nirvet.com via the visitor's own mail client. The address is also shown in plain text as the primary
// channel, so the page works even if mailto is unavailable. All validation is client-side and non-blocking.

import { useState } from "react";
import { Icon } from "@/components/icons";
import { CONTACT_EMAIL } from "@/components/site";

const INTERESTS = ["Request a demo", "Talk to sales", "Managed SOC (MSSP)", "Partnerships", "Support", "Other"];

export function ContactForm() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
  const [interest, setInterest] = useState(INTERESTS[0]);
  const [message, setMessage] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");

  const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const canSubmit = name.trim().length > 1 && emailValid && message.trim().length > 4;

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) {
      setError("Please add your name, a valid email, and a short message.");
      return;
    }
    setError("");
    const subject = `[${interest}] Nirvet enquiry from ${name.trim()}${company.trim() ? ` (${company.trim()})` : ""}`;
    const body = [
      `Name: ${name.trim()}`,
      `Email: ${email.trim()}`,
      company.trim() ? `Company: ${company.trim()}` : "",
      `Interest: ${interest}`,
      "",
      message.trim(),
    ]
      .filter(Boolean)
      .join("\n");
    // Opens the visitor's mail client addressed to contact@nirvet.com with everything pre-filled.
    window.location.href = `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    setSent(true);
  }

  const field = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", borderRadius: 10, color: "var(--c-ink)" } as const;
  const labelCls = "text-[13px] font-semibold";

  if (sent) {
    return (
      <div className="rounded-2xl p-8 text-center" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)" }}>
        <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl" style={{ background: "rgba(16,185,129,0.12)", color: "var(--c-ok)" }}>
          <Icon name="shield" size={26} />
        </div>
        <h3 className="text-lg font-bold">Your message is ready to send</h3>
        <p className="mx-auto mt-2 max-w-md text-sm leading-relaxed" style={{ color: "var(--c-ink-2)" }}>
          We opened your email client with the details pre-filled. If nothing appeared, email us directly at{" "}
          <a href={`mailto:${CONTACT_EMAIL}`} className="font-semibold" style={{ color: "var(--c-primary)" }}>{CONTACT_EMAIL}</a> and
          we&apos;ll get back to you within one business day.
        </p>
        <button onClick={() => setSent(false)} className="mt-6 rounded-lg px-5 py-2.5 text-sm font-semibold" style={{ color: "var(--c-primary)", border: "1px solid var(--c-primary)" }}>
          Send another message
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} className="rounded-2xl p-7 md:p-8" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)" }}>
      <div className="grid gap-5 sm:grid-cols-2">
        <label className="flex flex-col gap-2">
          <span className={labelCls}>Full name *</span>
          <input value={name} onChange={(e) => setName(e.target.value)} required placeholder="Ada Okoro" className="px-3.5 py-2.5 text-sm outline-none" style={field} />
        </label>
        <label className="flex flex-col gap-2">
          <span className={labelCls}>Work email *</span>
          <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" required placeholder="ada@acme.com" className="px-3.5 py-2.5 text-sm outline-none" style={field} />
        </label>
        <label className="flex flex-col gap-2">
          <span className={labelCls}>Company</span>
          <input value={company} onChange={(e) => setCompany(e.target.value)} placeholder="Acme Financial" className="px-3.5 py-2.5 text-sm outline-none" style={field} />
        </label>
        <label className="flex flex-col gap-2">
          <span className={labelCls}>I&apos;m interested in</span>
          <select value={interest} onChange={(e) => setInterest(e.target.value)} className="px-3.5 py-2.5 text-sm outline-none" style={field}>
            {INTERESTS.map((i) => (
              <option key={i} value={i}>{i}</option>
            ))}
          </select>
        </label>
      </div>
      <label className="mt-5 flex flex-col gap-2">
        <span className={labelCls}>How can we help? *</span>
        <textarea value={message} onChange={(e) => setMessage(e.target.value)} required rows={5} placeholder="Tell us about your environment, use case, or the problem you're trying to solve." className="px-3.5 py-2.5 text-sm outline-none" style={{ ...field, resize: "vertical" }} />
      </label>
      {error && <p className="mt-3 text-[13px]" style={{ color: "var(--c-danger)" }}>{error}</p>}
      <div className="mt-6 flex flex-wrap items-center gap-4">
        <button type="submit" disabled={!canSubmit} className="rounded-lg px-6 py-3 text-sm font-semibold text-white transition disabled:opacity-50" style={{ background: "var(--c-primary)" }}>
          Send message
        </button>
        <span className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>
          Or email us directly at{" "}
          <a href={`mailto:${CONTACT_EMAIL}`} className="font-medium" style={{ color: "var(--c-primary)" }}>{CONTACT_EMAIL}</a>
        </span>
      </div>
      <p className="mt-4 text-[11px] leading-relaxed" style={{ color: "var(--c-ink-3)" }}>
        By submitting, you agree to be contacted about your enquiry. We handle your details per our{" "}
        <a href="/legal/privacy" className="underline" style={{ color: "var(--c-ink-2)" }}>Privacy Policy</a>. We never sell your data.
      </p>
    </form>
  );
}
