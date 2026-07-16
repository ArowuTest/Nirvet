"use client";

// Customer approval landing (§6.11 #188) — the PUBLIC page an emailed single-use approval link lands on. The
// backend POST /soar/approve-link has always existed and been session-less (the token IS the capability), but
// nothing landed the link: no minter UI, no emailer, no page. So the whole email-approval path was unreachable —
// the API-only twin of the reachability defects this codebase has been closing. This is the landing half; the
// minter half is the "Customer approval link" button on the incident response panel.
//
// SAFETY: this page NEVER auto-submits on load. POSTing the token approves and consumes it atomically, so an email
// security scanner or link-preview crawler that merely FETCHES the URL must not be able to fire a containment
// approval. Approval requires a deliberate button click — exactly like accept-invitation requires an explicit
// submit. The token cannot be previewed (the endpoint has no read side; consuming it is the approval), so we say
// plainly what clicking authorizes rather than showing run internals.

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { apiPost, ApiError } from "@/lib/api";

function ShieldLogo() {
  return (
    <svg width="36" height="36" viewBox="0 0 36 36" fill="none" aria-hidden="true">
      <path d="M18 3L33 8.5V18C33 26.5 18 33 18 33C18 33 3 26.5 3 18V8.5L18 3Z" fill="rgba(14,165,233,0.12)" stroke="#0EA5E9" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M12 12L12 24L24 12L24 24" stroke="#0EA5E9" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="24" cy="24" r="2.5" fill="#06B6D4" />
    </svg>
  );
}

function Wordmark() {
  return (
    <div className="mb-8 flex items-center gap-2.5">
      <ShieldLogo />
      <span className="text-xl font-extrabold tracking-tight">NIR<span style={{ color: "var(--c-primary)" }}>VET</span></span>
    </div>
  );
}

function ApproveForm() {
  const params = useSearchParams();
  const token = params.get("token") ?? "";

  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function approve() {
    setError(null);
    if (!token) {
      setError("This approval link is missing its token. Ask your security team to re-send it.");
      return;
    }
    setBusy(true);
    try {
      // The response is the run, but it may carry internal fields; the customer only needs the outcome.
      await apiPost("/soar/approve-link", { token });
      setDone(true);
    } catch (e) {
      // The backend applies customerSafeError (J3), so any message here is already audience-safe. Still map the
      // common statuses to plain language.
      if (e instanceof ApiError && (e.status === 401 || e.status === 404)) {
        setError("This approval link is invalid or has already been used. Approval links are single-use.");
      } else if (e instanceof ApiError && e.status === 409) {
        setError("This request is no longer awaiting approval — it may have expired, been approved, or been withdrawn.");
      } else if (e instanceof ApiError && e.message) {
        setError(e.message);
      } else {
        setError("Could not record the approval. Please try again, or contact your security team.");
      }
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div className="w-full max-w-[400px]">
        <Wordmark />
        <div className="mb-6 flex items-start gap-2.5 rounded-[10px] p-4" style={{ background: "rgba(16,185,129,0.06)", border: "1px solid rgba(16,185,129,0.25)" }}>
          <span className="mt-1 inline-block h-2 w-2 shrink-0 rounded-full" style={{ background: "var(--c-ok)", boxShadow: "0 0 8px rgba(16,185,129,0.6)" }} />
          <div>
            <p className="text-sm font-semibold">Approval recorded</p>
            <p className="mt-1 text-[13px]" style={{ color: "var(--c-ink-2)" }}>
              Your security team has been authorized to proceed with the requested containment action. You can close this page.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-[400px]">
      <Wordmark />
      <p className="mb-2 text-xs font-semibold uppercase tracking-[0.08em]" style={{ color: "var(--c-primary)" }}>Containment approval</p>
      <h2 className="mb-1.5 text-2xl font-bold tracking-tight">Authorize a security action</h2>
      <p className="mb-6 text-sm" style={{ color: "var(--c-ink-2)" }}>
        Your security operations team has requested your approval to run a containment action on your environment —
        such as isolating a host or disabling an account. Approving authorizes them to proceed.
      </p>

      {error && (
        <p className="mb-4 text-sm" style={{ color: "var(--c-danger)" }} role="alert">{error}</p>
      )}

      <button
        onClick={approve}
        disabled={busy || !token}
        className="flex w-full items-center justify-center gap-2 rounded-[10px] py-2.5 text-sm font-semibold text-white transition disabled:opacity-50"
        style={{ background: "var(--c-primary)" }}
      >
        {busy ? "Recording approval…" : "Approve containment"}
      </button>

      <div className="mt-6 flex items-start gap-2.5 rounded-[10px] p-3.5" style={{ background: "rgba(14,165,233,0.04)", border: "1px solid var(--c-border)" }}>
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="mt-0.5 shrink-0" aria-hidden="true">
          <path d="M8 1L14 3.5V8C14 12 8 15 8 15C8 15 2 12 2 8V3.5L8 1Z" stroke="#0EA5E9" strokeWidth="1.3" strokeLinejoin="round" />
        </svg>
        <p className="text-xs leading-relaxed" style={{ color: "var(--c-ink-3)" }}>
          This link is single-use and expires. Nothing happens until you press Approve. If you did not expect this
          request, do not approve it — contact your security team. All approvals are recorded to an immutable audit trail.
        </p>
      </div>
    </div>
  );
}

export default function ApproveContainmentPage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-6 py-12" style={{ background: "var(--c-bg)" }}>
      <Suspense fallback={<div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>}>
        <ApproveForm />
      </Suspense>
    </main>
  );
}
