"use client";

// Settings — the caller's own account & security surface. Everything here is authed (no role gate) and scoped
// server-side to the caller: identity from GET /me, password change via POST /me/password
// {current_password,new_password}, the in-app feed toggle (GET/PUT /notify/inbox/prefs), and session controls
// (sign out everywhere). Tenant-level policies (SLA, correlation, escalation) are admin-managed elsewhere — we
// say so rather than render controls the caller can't use.

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { apiGet, apiPost, apiPut, getMe, logoutAll, ApiError, type Me } from "@/lib/api";
import { PageHeader, Panel, StatusTag, Button } from "@/components/ui";

export default function SettingsPage() {
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);
  const [feed, setFeed] = useState(true);

  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pwMsg, setPwMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  // MFA enrollment (TOTP). Enroll returns an otpauth URI + shared secret; activation confirms a code.
  const [mfaStep, setMfaStep] = useState<"idle" | "activating">("idle");
  const [mfaPw, setMfaPw] = useState("");
  const [mfaSecret, setMfaSecret] = useState("");
  const [mfaURI, setMfaURI] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaMsg, setMfaMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);

  const load = useCallback(async () => {
    const [m, p] = await Promise.allSettled([getMe(), apiGet<{ in_app_enabled: boolean }>("/notify/inbox/prefs")]);
    if (m.status === "fulfilled") setMe(m.value);
    if (p.status === "fulfilled") setFeed(p.value.in_app_enabled);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function changePassword() {
    setPwMsg(null);
    if (next.length < 8) return setPwMsg({ tone: "danger", text: "New password must be at least 8 characters." });
    if (next !== confirm) return setPwMsg({ tone: "danger", text: "New password and confirmation don't match." });
    setBusy(true);
    try {
      await apiPost("/me/password", { current_password: cur, new_password: next });
      setPwMsg({ tone: "ok", text: "Password changed." });
      setCur("");
      setNext("");
      setConfirm("");
    } catch (e) {
      const m = e instanceof ApiError ? e.message : "Could not change password.";
      setPwMsg({ tone: "danger", text: m });
    } finally {
      setBusy(false);
    }
  }

  async function enrollMfa() {
    setMfaMsg(null);
    try {
      const r = await apiPost<{ otpauth_uri: string; secret: string }>("/mfa/enroll", { current_password: mfaPw });
      setMfaSecret(r.secret);
      setMfaURI(r.otpauth_uri);
      setMfaStep("activating");
      setMfaPw("");
    } catch (e) {
      setMfaMsg({ tone: "danger", text: e instanceof ApiError ? e.message : "Could not start MFA enrollment." });
    }
  }
  async function activateMfa() {
    setMfaMsg(null);
    try {
      await apiPost("/mfa/activate", { code: mfaCode });
      setMfaStep("idle");
      setMfaSecret("");
      setMfaURI("");
      setMfaCode("");
      setMfaMsg({ tone: "ok", text: "Multi-factor authentication enabled." });
      await load();
    } catch (e) {
      setMfaMsg({ tone: "danger", text: e instanceof ApiError ? e.message : "Invalid code — try again." });
    }
  }
  async function disableMfa() {
    setMfaMsg(null);
    try {
      await apiPost("/mfa/disable", { code: mfaCode });
      setMfaCode("");
      setMfaMsg({ tone: "ok", text: "Multi-factor authentication disabled." });
      await load();
    } catch (e) {
      setMfaMsg({ tone: "danger", text: e instanceof ApiError ? e.message : "Invalid code." });
    }
  }

  async function toggleFeed() {
    const v = !feed;
    setFeed(v);
    await apiPut("/notify/inbox/prefs", { in_app_enabled: v }).catch(() => setFeed(!v));
  }

  async function signOutAll() {
    try {
      await logoutAll();
    } catch {
      /* clear regardless */
    }
    router.replace("/login");
  }

  const input = {
    background: "var(--c-surface-2)",
    border: "1px solid var(--c-border)",
    color: "var(--c-ink)",
  } as const;

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <PageHeader title="Settings" sub="Your account, security and notification preferences" />

      <Panel title="Account">
        <div className="grid grid-cols-2 gap-5 text-sm">
          <Field label="Email">{me?.email ?? "—"}</Field>
          <Field label="Role">{me?.role?.replace(/_/g, " ") ?? "—"}</Field>
          <Field label="Tenant"><span className="font-mono text-xs">{me?.tenant_id ?? "—"}</span></Field>
          <Field label="Multi-factor auth">
            {me?.mfa_enabled ? <StatusTag tone="ok">Enabled</StatusTag> : <StatusTag tone="warn">Not enabled</StatusTag>}
          </Field>
        </div>
      </Panel>

      <Panel title="Multi-factor authentication" sub="A time-based one-time code (TOTP) from an authenticator app, required in addition to your password">
        {me?.role === "platform_admin" && !me?.mfa_enabled && (
          <div className="mb-4 rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(239,68,68,0.12)", color: "#ef4444", border: "1px solid var(--c-border)" }}>
            MFA is required for platform-admin accounts. Enable it now to secure operator access.
          </div>
        )}
        {mfaMsg && <div className="mb-3 text-[13px]" style={{ color: mfaMsg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{mfaMsg.text}</div>}

        {me?.mfa_enabled ? (
          <div className="max-w-sm space-y-3">
            <p className="text-sm" style={{ color: "var(--c-ink-2)" }}>MFA is enabled on your account. To disable it, confirm a current code.</p>
            <input value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} inputMode="numeric" placeholder="6-digit code" className="w-40 rounded-lg px-3 py-2 text-sm" style={input} />
            <div><Button variant="danger" size="sm" disabled={!mfaCode} onClick={disableMfa}>Disable MFA</Button></div>
          </div>
        ) : mfaStep === "activating" ? (
          <div className="max-w-md space-y-3">
            <p className="text-sm" style={{ color: "var(--c-ink-2)" }}>Add this account to your authenticator app, then enter the 6-digit code it shows to finish.</p>
            <div>
              <div className="text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Secret key (manual entry)</div>
              <div className="mt-1 flex items-center gap-2">
                <code className="rounded px-2 py-1.5 font-mono text-sm" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" }}>{mfaSecret}</code>
                <button onClick={() => navigator.clipboard?.writeText(mfaSecret)} className="text-[11px]" style={{ color: "var(--c-primary)" }}>Copy</button>
              </div>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>otpauth URI</div>
              <div className="mt-1 flex items-center gap-2">
                <code className="max-w-full truncate rounded px-2 py-1.5 font-mono text-[11px]" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink-2)" }} title={mfaURI}>{mfaURI}</code>
                <button onClick={() => navigator.clipboard?.writeText(mfaURI)} className="text-[11px] shrink-0" style={{ color: "var(--c-primary)" }}>Copy</button>
              </div>
            </div>
            <input value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} inputMode="numeric" placeholder="6-digit code" className="w-40 rounded-lg px-3 py-2 text-sm" style={input} />
            <div className="flex gap-2">
              <Button size="sm" disabled={!mfaCode} onClick={activateMfa}>Verify &amp; enable</Button>
              <Button size="sm" variant="ghost" onClick={() => { setMfaStep("idle"); setMfaSecret(""); setMfaURI(""); setMfaCode(""); }}>Cancel</Button>
            </div>
          </div>
        ) : (
          <div className="max-w-sm space-y-3">
            <p className="text-sm" style={{ color: "var(--c-ink-2)" }}>Confirm your password to begin setting up MFA.</p>
            <input type="password" value={mfaPw} onChange={(e) => setMfaPw(e.target.value)} placeholder="Current password" className="w-full rounded-lg px-3 py-2 text-sm" style={input} autoComplete="current-password" />
            <div><Button size="sm" disabled={!mfaPw} onClick={enrollMfa}>Set up MFA</Button></div>
          </div>
        )}
      </Panel>

      <Panel title="Change password" sub="Choose a strong, unique password of at least 8 characters">
        <div className="max-w-sm space-y-3">
          {[
            ["Current password", cur, setCur] as const,
            ["New password", next, setNext] as const,
            ["Confirm new password", confirm, setConfirm] as const,
          ].map(([label, val, set]) => (
            <label key={label} className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
              {label}
              <input type="password" value={val} onChange={(e) => set(e.target.value)} className="mt-1 w-full rounded-lg px-3 py-2 text-sm outline-none" style={input} autoComplete="off" />
            </label>
          ))}
          {pwMsg && <p className="text-[13px]" style={{ color: pwMsg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{pwMsg.text}</p>}
          <Button disabled={busy || !cur || !next} onClick={changePassword}>{busy ? "Saving…" : "Change password"}</Button>
        </div>
      </Panel>

      <Panel title="Notifications">
        <label className="flex items-center justify-between">
          <span className="text-sm" style={{ color: "var(--c-ink-2)" }}>In-app notification feed</span>
          <input type="checkbox" checked={feed} onChange={toggleFeed} />
        </label>
      </Panel>

      <Panel title="Tenant administration" sub="SLA, correlation, session, escalation and authority-to-act policy (tenant-admin)">
        <Link href="/console/settings/tenant" className="inline-flex rounded-lg px-3.5 py-2 text-sm font-semibold" style={{ border: "1px solid var(--c-border-strong)", color: "var(--c-primary)" }}>
          Open tenant governance →
        </Link>
      </Panel>

      <Panel title="Sessions">
        <div className="flex items-center justify-between">
          <span className="text-sm" style={{ color: "var(--c-ink-2)" }}>Sign out of every device</span>
          <Button variant="danger" size="sm" onClick={signOutAll}>Sign out everywhere</Button>
        </div>
      </Panel>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>{label}</div>
      <div className="mt-1" style={{ color: "var(--c-ink)" }}>{children}</div>
    </div>
  );
}
