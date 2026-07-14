"use client";

// Invitation acceptance — the invitee sets a password to activate the account an admin invited
// (SRS §6.2 IAM-001/008). Drives the PUBLIC backend endpoint POST /auth/invitations/accept
// {token, password}; the one-time token arrives in the ?token= query param of the invite link.
// This screen existed only in the backend (no UI drove it) until now — it is the activation half of
// the admin "Invitations" panel in Identity & access.

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { apiPost, ApiError } from "@/lib/api";

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

function AcceptForm() {
  const router = useRouter();
  const params = useSearchParams();
  const token = params.get("token") ?? "";

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<{ email: string; role: string } | null>(null);

  const inputCls =
    "w-full rounded-[10px] border px-3.5 py-2.5 text-sm text-[var(--c-ink)] outline-none transition placeholder:text-[var(--c-ink-3)] focus:border-[var(--c-primary)]";
  const inputStyle = { background: "var(--c-surface)", borderColor: "var(--c-border)" } as const;

  async function submit() {
    setError(null);
    if (!token) {
      setError("This invitation link is missing its token. Ask your administrator to re-send it.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      const res = await apiPost<{ status: string; email: string; role: string }>(
        "/auth/invitations/accept",
        { token, password },
      );
      setDone({ email: res.email, role: res.role });
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setError("This invitation is invalid or has already been used.");
      } else if (e instanceof ApiError && e.status === 409) {
        setError("This invitation has expired or was already accepted. Ask for a new one.");
      } else if (e instanceof ApiError && e.status === 400) {
        setError(e.message || "Please choose a stronger password.");
      } else {
        setError("Could not activate the account. Please try again.");
      }
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div className="w-full max-w-[380px]">
        <div className="mb-8 flex items-center gap-2.5">
          <ShieldLogo />
          <span className="text-xl font-extrabold tracking-tight">
            NIR<span style={{ color: "var(--c-primary)" }}>VET</span>
          </span>
        </div>
        <div
          className="mb-6 flex items-start gap-2.5 rounded-[10px] p-4"
          style={{ background: "rgba(16,185,129,0.06)", border: "1px solid rgba(16,185,129,0.25)" }}
        >
          <span
            className="mt-1 inline-block h-2 w-2 shrink-0 rounded-full"
            style={{ background: "var(--c-ok)", boxShadow: "0 0 8px rgba(16,185,129,0.6)" }}
          />
          <div>
            <p className="text-sm font-semibold">Account activated</p>
            <p className="mt-1 text-[13px]" style={{ color: "var(--c-ink-2)" }}>
              {done.email} is now active as <span className="font-medium">{done.role.replace(/_/g, " ")}</span>. You can
              sign in with your new password.
            </p>
          </div>
        </div>
        <button
          onClick={() => router.replace("/login")}
          className="flex w-full items-center justify-center gap-2 rounded-[10px] py-2.5 text-sm font-semibold text-white transition"
          style={{ background: "var(--c-primary)" }}
        >
          Go to sign-in
        </button>
      </div>
    );
  }

  return (
    <div className="w-full max-w-[380px]">
      <div className="mb-8 flex items-center gap-2.5">
        <ShieldLogo />
        <span className="text-xl font-extrabold tracking-tight">
          NIR<span style={{ color: "var(--c-primary)" }}>VET</span>
        </span>
      </div>

      <p className="mb-2 text-xs font-semibold uppercase tracking-[0.08em]" style={{ color: "var(--c-primary)" }}>
        Activate your account
      </p>
      <h2 className="mb-1.5 text-2xl font-bold tracking-tight">Set your password</h2>
      <p className="mb-8 text-sm" style={{ color: "var(--c-ink-2)" }}>
        You&apos;ve been invited to a Nirvet workspace. Choose a password to activate your account.
      </p>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
        className="space-y-4"
      >
        <div>
          <label className="mb-1.5 block text-[13px] font-medium" style={{ color: "var(--c-ink-2)" }}>
            New password
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="At least 8 characters"
            autoComplete="new-password"
            required
            className={inputCls}
            style={inputStyle}
          />
        </div>
        <div>
          <label className="mb-1.5 block text-[13px] font-medium" style={{ color: "var(--c-ink-2)" }}>
            Confirm password
          </label>
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="Re-enter your password"
            autoComplete="new-password"
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
          {busy ? "Activating…" : "Activate account"}
        </button>
      </form>

      <div
        className="mt-6 flex items-start gap-2.5 rounded-[10px] p-3.5"
        style={{ background: "rgba(14,165,233,0.04)", border: "1px solid var(--c-border)" }}
      >
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="mt-0.5 shrink-0" aria-hidden="true">
          <path d="M8 1L14 3.5V8C14 12 8 15 8 15C8 15 2 12 2 8V3.5L8 1Z" stroke="#0EA5E9" strokeWidth="1.3" strokeLinejoin="round" />
        </svg>
        <p className="text-xs leading-relaxed" style={{ color: "var(--c-ink-3)" }}>
          This invitation link is single-use and expires. Your password is hashed and never stored in plaintext; all
          activations are recorded to the immutable audit trail.
        </p>
      </div>
    </div>
  );
}

export default function AcceptInvitationPage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-6 py-12" style={{ background: "var(--c-bg)" }}>
      <Suspense fallback={<div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>}>
        <AcceptForm />
      </Suspense>
    </main>
  );
}
