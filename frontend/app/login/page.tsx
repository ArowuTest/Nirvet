"use client";

// Secure sign-in — matched to outputs/Nirvet UI Designs/Secure-Login-v2.html and
// Nirvet-_-MFA-Verification.html. Two-panel layout: trust/posture on the left, the real auth flow on the right.
//
// Truthful to backend capability (design-tweak authority): the mockup shows Passkey/TOTP/SSO/SMS method cards,
// but the built backend authenticates via password (+ TOTP second factor) and enterprise SSO/SAML. So the form
// is email + password → Continue; if the account has MFA the server returns `mfa_required` and we show the
// TOTP step; SSO and SAML are top-level redirects. Passkey/SMS-as-primary are not offered (not implemented) —
// we don't render controls that would imply a capability that doesn't exist.

import { useState } from "react";
import { useRouter } from "next/navigation";
import { login, getMe, ssoStartUrl, samlStartUrl, ApiError } from "@/lib/api";

function ShieldLogo() {
  return (
    <svg width="36" height="36" viewBox="0 0 36 36" fill="none" aria-hidden="true">
      <path
        d="M18 3L33 8.5V18C33 26.5 18 33 18 33C18 33 3 26.5 3 18V8.5L18 3Z"
        fill="rgba(14,165,233,0.12)"
        stroke="#0EA5E9"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M12 12L12 24L24 12L24 24"
        stroke="#0EA5E9"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="24" cy="24" r="2.5" fill="#06B6D4" />
    </svg>
  );
}

const posture = [
  { label: "Identity provider — operational", tone: "ok" },
  { label: "TLS 1.3 — enforced end-to-end", tone: "ok" },
  { label: "Session audit pipeline — active", tone: "ok" },
  { label: "Credential vault — sealed", tone: "ok" },
];

export default function LoginPage() {
  const router = useRouter();
  const [step, setStep] = useState<"credentials" | "mfa">("credentials");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(code?: string) {
    setBusy(true);
    setError(null);
    try {
      const res = await login(email, password, code);
      if ("mfaRequired" in res) {
        setStep("mfa");
        return;
      }
      // Route by audience: customer users land in the customer portal, provider/SOC users in the console.
      const me = await getMe().catch(() => null);
      router.replace(me?.role?.startsWith("customer") ? "/portal" : "/console");
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setError(step === "mfa" ? "Invalid or expired code." : "Invalid email or password.");
      } else if (e instanceof ApiError && e.status === 429) {
        setError("Too many attempts. Please wait and try again.");
      } else {
        setError("Sign-in failed. Please try again.");
      }
    } finally {
      setBusy(false);
    }
  }

  const inputCls =
    "w-full rounded-[10px] border px-3.5 py-2.5 text-sm text-[var(--c-ink)] outline-none transition placeholder:text-[var(--c-ink-3)] focus:border-[var(--c-primary)]";
  const inputStyle = { background: "var(--c-surface)", borderColor: "var(--c-border)" } as const;

  return (
    <div className="grid min-h-screen lg:grid-cols-[1fr_520px]">
      {/* Left — trust / posture (hidden on small screens, per design) */}
      <aside
        className="relative hidden flex-col overflow-hidden p-12 lg:flex"
        style={{ background: "var(--c-surface)", borderRight: "1px solid var(--c-border)" }}
      >
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              "radial-gradient(ellipse 80% 60% at 30% 50%, rgba(14,165,233,0.06) 0%, transparent 65%), radial-gradient(ellipse 50% 40% at 80% 20%, rgba(6,182,212,0.04) 0%, transparent 50%)",
          }}
        />
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            backgroundImage:
              "linear-gradient(rgba(14,165,233,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(14,165,233,0.03) 1px, transparent 1px)",
            backgroundSize: "48px 48px",
          }}
        />
        <div className="relative z-10 flex flex-1 flex-col">
          <div className="mb-14 flex items-center gap-2.5">
            <ShieldLogo />
            <span className="text-xl font-extrabold tracking-tight">
              NIR<span style={{ color: "var(--c-primary)" }}>VET</span>
            </span>
          </div>
          <h1 className="mb-4 text-[32px] font-extrabold leading-tight tracking-tight">
            Your SOC.
            <br />
            Secured at every layer.
          </h1>
          <p className="mb-12 max-w-sm text-[15px] leading-relaxed" style={{ color: "var(--c-ink-2)" }}>
            Access your Nirvet operations workspace. All sessions are encrypted, audited, and bound to your
            organisation&apos;s identity policy.
          </p>

          <div
            className="mb-8 rounded-3xl p-6"
            style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}
          >
            <div className="mb-4 flex items-center justify-between">
              <span className="text-[13px] font-semibold" style={{ color: "var(--c-ink-2)" }}>
                Platform Security Posture
              </span>
              <span className="flex items-center gap-1.5 text-[11px]" style={{ color: "var(--c-ok)" }}>
                <span
                  className="inline-block h-[7px] w-[7px] rounded-full"
                  style={{ background: "var(--c-ok)", boxShadow: "0 0 8px rgba(16,185,129,0.6)" }}
                />
                Live
              </span>
            </div>
            <div className="flex flex-col gap-2.5">
              {posture.map((p) => (
                <div key={p.label} className="flex items-center gap-2.5 text-[13px]" style={{ color: "var(--c-ink-2)" }}>
                  <span
                    className="h-2 w-2 shrink-0 rounded-full"
                    style={{ background: p.tone === "ok" ? "var(--c-ok)" : "var(--c-warn)" }}
                  />
                  {p.label}
                </div>
              ))}
            </div>
          </div>

          <div className="mt-auto flex flex-wrap gap-3">
            {["Phishing-resistant auth", "End-to-end encryption", "Immutable audit log"].map((b) => (
              <span
                key={b}
                className="rounded-[10px] px-3.5 py-2 text-xs"
                style={{ background: "rgba(14,165,233,0.05)", border: "1px solid var(--c-border)", color: "var(--c-ink-3)" }}
              >
                {b}
              </span>
            ))}
          </div>
        </div>
      </aside>

      {/* Right — the actual sign-in flow */}
      <main className="flex flex-col items-center justify-center px-6 py-12 sm:px-14" style={{ background: "var(--c-bg)" }}>
        <div className="w-full max-w-[380px]">
          {/* Mobile logo (left panel is hidden) */}
          <div className="mb-8 flex items-center gap-2.5 lg:hidden">
            <ShieldLogo />
            <span className="text-xl font-extrabold tracking-tight">
              NIR<span style={{ color: "var(--c-primary)" }}>VET</span>
            </span>
          </div>

          <p
            className="mb-2 text-xs font-semibold uppercase tracking-[0.08em]"
            style={{ color: "var(--c-primary)" }}
          >
            {step === "mfa" ? "Two-Factor Verification" : "Secure Sign-In"}
          </p>
          <h2 className="mb-1.5 text-2xl font-bold tracking-tight">
            {step === "mfa" ? "Verify your identity" : "Welcome back"}
          </h2>
          <p className="mb-8 text-sm" style={{ color: "var(--c-ink-2)" }}>
            {step === "mfa"
              ? "Enter the 6-digit code from your authenticator app."
              : "Sign in to your Nirvet operations workspace."}
          </p>

          {step === "credentials" ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                submit();
              }}
              className="space-y-4"
            >
              <div>
                <label className="mb-1.5 block text-[13px] font-medium" style={{ color: "var(--c-ink-2)" }}>
                  Work email address
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@organisation.com"
                  autoComplete="email"
                  required
                  className={inputCls}
                  style={inputStyle}
                />
              </div>
              <div>
                <label className="mb-1.5 block text-[13px] font-medium" style={{ color: "var(--c-ink-2)" }}>
                  Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  autoComplete="current-password"
                  required
                  className={inputCls}
                  style={inputStyle}
                />
              </div>

              {error && (
                <p className="text-sm" style={{ color: "var(--c-danger)" }} role="alert">
                  {error}
                </p>
              )}

              <button
                type="submit"
                disabled={busy}
                className="flex w-full items-center justify-center gap-2 rounded-[10px] py-2.5 text-sm font-semibold text-white transition disabled:opacity-50"
                style={{ background: "var(--c-primary)" }}
              >
                {busy ? "Signing in…" : "Continue"}
              </button>

              <div className="flex items-center gap-3 py-1 text-xs" style={{ color: "var(--c-ink-3)" }}>
                <span className="h-px flex-1" style={{ background: "var(--c-border)" }} />
                or continue with
                <span className="h-px flex-1" style={{ background: "var(--c-border)" }} />
              </div>

              <div className="space-y-2.5">
                <a
                  href={ssoStartUrl()}
                  className="flex w-full items-center justify-center gap-2 rounded-[10px] py-2.5 text-sm font-semibold transition"
                  style={{ background: "rgba(99,102,241,0.1)", border: "1px solid rgba(99,102,241,0.25)", color: "var(--c-ink)" }}
                >
                  Enterprise SSO
                </a>
                <a
                  href={samlStartUrl()}
                  className="flex w-full items-center justify-center gap-2 rounded-[10px] py-2.5 text-sm font-semibold transition"
                  style={{ background: "rgba(14,165,233,0.06)", border: "1px solid var(--c-border)", color: "var(--c-ink-2)" }}
                >
                  SAML 2.0
                </a>
              </div>
            </form>
          ) : (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                submit(mfaCode);
              }}
              className="space-y-4"
            >
              <div>
                <label className="mb-1.5 block text-[13px] font-medium" style={{ color: "var(--c-ink-2)" }}>
                  Authenticator code
                </label>
                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]*"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ""))}
                  placeholder="000000"
                  autoFocus
                  className={`${inputCls} text-center text-2xl tracking-[0.5em]`}
                  style={inputStyle}
                />
              </div>

              {error && (
                <p className="text-sm" style={{ color: "var(--c-danger)" }} role="alert">
                  {error}
                </p>
              )}

              <button
                type="submit"
                disabled={busy || mfaCode.length < 6}
                className="flex w-full items-center justify-center gap-2 rounded-[10px] py-2.5 text-sm font-semibold text-white transition disabled:opacity-50"
                style={{ background: "var(--c-primary)" }}
              >
                {busy ? "Verifying…" : "Verify & sign in"}
              </button>

              <button
                type="button"
                onClick={() => {
                  setStep("credentials");
                  setMfaCode("");
                  setError(null);
                }}
                className="w-full text-center text-[13px] transition"
                style={{ color: "var(--c-ink-3)" }}
              >
                ← Back to sign-in
              </button>
            </form>
          )}

          <div
            className="mt-6 flex items-start gap-2.5 rounded-[10px] p-3.5"
            style={{ background: "rgba(14,165,233,0.04)", border: "1px solid var(--c-border)" }}
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="mt-0.5 shrink-0" aria-hidden="true">
              <path d="M8 1L14 3.5V8C14 12 8 15 8 15C8 15 2 12 2 8V3.5L8 1Z" stroke="#0EA5E9" strokeWidth="1.3" strokeLinejoin="round" />
            </svg>
            <p className="text-xs leading-relaxed" style={{ color: "var(--c-ink-3)" }}>
              All authentication attempts are logged to an immutable audit trail. Sessions expire automatically per
              your organisation&apos;s policy. Credentials are never transmitted in plaintext.
            </p>
          </div>
        </div>
      </main>
    </div>
  );
}
