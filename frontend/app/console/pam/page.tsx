"use client";

// Privileged Access Management (SRS §6.2 IAM-004/006). Two surfaces on one page:
//   (1) Self-service — every user can request a time-bounded elevation, invoke break-glass (emergency,
//       auto-granted + post-use review), see their own elevations, and mint an elevated token for an active grant.
//   (2) Manager queue — soc_manager+ sees the tenant's pending elevations and approves/rejects (four-eyes:
//       the requester can never approve their own) + reviews break-glass grants. The queue GET is manager-gated
//       server-side, so we attempt it and simply hide the section on 403 (a non-manager sees only self-service).
// Wired to /me/elevations* (authed) and /admin/elevations* (manager). No hardcoding — durations clamp to the
// backend's 8h cap; grantable roles honour the provider/customer boundary the backend enforces.

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, getMe, ApiError, type Me } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, Button, EmptyState } from "@/components/ui";

type Elevation = {
  id: string;
  user_email: string;
  base_role: string;
  elevated_role: string;
  kind: string; // pam | break_glass
  reason: string;
  duration_seconds: number;
  status: string; // requested | active | rejected | expired
  approver_email?: string;
  granted_at?: string;
  expires_at?: string;
  review_required?: boolean;
  reviewed_by?: string;
  created_at: string;
};

const PROVIDER_ROLES = ["soc_manager", "analyst_t3", "analyst_t2", "analyst_t1", "detection_engineer"];
const CUSTOMER_ROLES = ["customer_admin", "customer_viewer"];
const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

function statusTone(s: string): "ok" | "warn" | "danger" | "neutral" | "info" {
  if (s === "active") return "ok";
  if (s === "requested") return "warn";
  if (s === "rejected") return "danger";
  return "neutral";
}
function isProviderRole(r: string) { return r.startsWith("analyst") || r === "soc_manager" || r === "detection_engineer" || r === "platform_admin"; }

export default function PamPage() {
  const [me, setMe] = useState<Me | null>(null);
  const [mine, setMine] = useState<Elevation[]>([]);
  const [queue, setQueue] = useState<Elevation[] | null>(null); // null until known; [] = empty; stays null if 403
  const [isManager, setIsManager] = useState(false);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [mintedFor, setMintedFor] = useState<{ id: string; role: string; expires: string } | null>(null);

  // request/break-glass form state
  const [role, setRole] = useState("");
  const [reason, setReason] = useState("");
  const [mins, setMins] = useState(60);
  const [confirmBG, setConfirmBG] = useState(false);
  const [rejectFor, setRejectFor] = useState<Elevation | null>(null);
  const [rejectReason, setRejectReason] = useState("");

  const grantable = me && isProviderRole(me.role) ? PROVIDER_ROLES : CUSTOMER_ROLES;

  const load = useCallback(async () => {
    const mineR = await apiGet<{ elevations: Elevation[] | null }>("/me/elevations").catch(() => ({ elevations: [] }));
    setMine(mineR.elevations ?? []);
    // Manager queue: attempt; a 403 means this user isn't a manager → leave hidden.
    try {
      const q = await apiGet<{ elevations: Elevation[] | null }>("/admin/elevations");
      setQueue(q.elevations ?? []);
      setIsManager(true);
    } catch {
      setQueue(null);
      setIsManager(false);
    }
  }, []);

  useEffect(() => {
    getMe().then((m) => { setMe(m); if (!role) setRole(isProviderRole(m.role) ? "analyst_t3" : "customer_admin"); }).catch(() => {});
    load();
  }, [load]); // eslint-disable-line react-hooks/exhaustive-deps

  async function run(fn: () => Promise<unknown>, ok: string, what: string) {
    setMsg(null);
    try { await fn(); setMsg({ tone: "ok", text: ok }); await load(); }
    catch (e) { setMsg({ tone: "danger", text: `${what}: ${e instanceof ApiError ? e.message : "failed"}` }); }
  }

  async function mint(id: string) {
    setMsg(null);
    try {
      const r = await apiPost<{ token: string; elevated_role: string; expires_at: string }>(`/me/elevations/${id}/token`, {});
      setMintedFor({ id, role: r.elevated_role, expires: r.expires_at });
      setMsg({ tone: "ok", text: "Elevated token minted — set it as your bearer to act with the elevated role." });
    } catch (e) { setMsg({ tone: "danger", text: `Mint token: ${e instanceof ApiError ? e.message : "failed"}` }); }
  }

  const body = () => ({ elevated_role: role, reason, duration_seconds: mins * 60 });

  return (
    <div>
      <PageHeader title="Privileged access" sub="Request a time-bounded elevation, break-glass in an emergency, or (managers) approve the queue" />

      {msg && (
        <div className="mb-4 rounded-lg px-4 py-2.5 text-sm" style={{ background: msg.tone === "ok" ? "var(--c-ok-bg, rgba(16,185,129,0.12))" : "rgba(239,68,68,0.12)", color: msg.tone === "ok" ? "var(--c-ok, #10b981)" : "#ef4444", border: "1px solid var(--c-border)" }}>{msg.text}</div>
      )}

      {mintedFor && (
        <Panel title="Elevated session" sub={`Role ${mintedFor.role.replace(/_/g, " ")} · expires ${new Date(mintedFor.expires).toLocaleString()}`}>
          <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>
            The elevated token is issued to your session for this grant. Use it as your bearer for privileged calls until it expires;
            all actions under it are audited and (for break-glass) require post-use review.
          </p>
        </Panel>
      )}

      {/* Self-service: request + break-glass */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Request elevation" sub="Time-bounded, justified, requires manager approval (four-eyes)">
          <div className="grid gap-3">
            <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Elevated role
              <select value={role} onChange={(e) => setRole(e.target.value)} className="mt-1 w-full rounded-lg px-3 py-2 text-sm capitalize" style={inputStyle}>
                {grantable.map((r) => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}
              </select>
            </label>
            <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Justification
              <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} placeholder="Why do you need this access?" className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} />
            </label>
            <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Duration (minutes, max 480)
              <input type="number" min={5} max={480} value={mins} onChange={(e) => setMins(Math.max(5, Math.min(480, Number(e.target.value))))} className="mt-1 w-40 rounded-lg px-3 py-2 text-sm" style={inputStyle} />
            </label>
            <div><Button size="sm" disabled={!reason.trim()} onClick={() => run(() => apiPost("/me/elevations", body()).then(() => setReason("")), "Elevation requested — awaiting manager approval.", "Request")}>Request elevation</Button></div>
          </div>
        </Panel>

        <Panel title="Break-glass (emergency)" sub="Auto-granted with a mandatory reason + post-use review. Use only in a genuine emergency.">
          <div className="grid gap-3">
            <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Emergency reason
              <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} placeholder="Describe the emergency" className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} />
            </label>
            <p className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>Elevates the role selected above by at most one tier, immediately. An alert fires and a review is required afterwards.</p>
            <div><Button size="sm" variant="danger" disabled={!reason.trim()} onClick={() => setConfirmBG(true)}>Invoke break-glass</Button></div>
          </div>
        </Panel>
      </div>

      {/* My elevations */}
      <Panel title="My elevations" bodyStyle={{ padding: 0 }}>
        {mine.length === 0 ? <div className="p-6"><EmptyState title="No elevations" hint="Your elevation requests and break-glass grants appear here." /></div> : (
          <Table head={<><Th>Role</Th><Th>Kind</Th><Th>Status</Th><Th>Reason</Th><Th>Expires</Th><Th className="text-right">Action</Th></>}>
            {mine.map((e) => (
              <tr key={e.id}>
                <Td className="capitalize font-medium">{e.elevated_role.replace(/_/g, " ")}</Td>
                <Td><StatusTag tone={e.kind === "break_glass" ? "danger" : "info"}>{e.kind.replace(/_/g, " ")}</StatusTag></Td>
                <Td><StatusTag tone={statusTone(e.status)}>{e.status}{e.review_required && !e.reviewed_by ? " · review due" : ""}</StatusTag></Td>
                <Td className="max-w-[220px] truncate text-xs" title={e.reason}>{e.reason}</Td>
                <Td className="text-xs">{e.expires_at ? new Date(e.expires_at).toLocaleString() : "—"}</Td>
                <Td className="text-right">{e.status === "active" ? <Button size="sm" variant="ghost" onClick={() => mint(e.id)}>Mint token</Button> : "—"}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>

      {/* Manager queue */}
      {isManager && (
        <Panel title="Elevation queue" sub="Pending requests + break-glass grants for this tenant. Four-eyes: you cannot approve your own." bodyStyle={{ padding: 0 }}>
          {(queue ?? []).length === 0 ? <div className="p-6"><EmptyState title="Queue empty" hint="Pending elevation requests will appear here for approval." /></div> : (
            <Table head={<><Th>User</Th><Th>Role</Th><Th>Kind</Th><Th>Status</Th><Th>Reason</Th><Th className="text-right">Decision</Th></>}>
              {(queue ?? []).map((e) => {
                const isSelf = me?.email === e.user_email;
                const pending = e.kind === "pam" && e.status === "requested";
                const reviewDue = e.kind === "break_glass" && e.review_required && !e.reviewed_by;
                return (
                  <tr key={e.id}>
                    <Td className="text-xs">{e.user_email}</Td>
                    <Td className="capitalize">{e.elevated_role.replace(/_/g, " ")}</Td>
                    <Td><StatusTag tone={e.kind === "break_glass" ? "danger" : "info"}>{e.kind.replace(/_/g, " ")}</StatusTag></Td>
                    <Td><StatusTag tone={statusTone(e.status)}>{e.status}</StatusTag></Td>
                    <Td className="max-w-[220px] truncate text-xs" title={e.reason}>{e.reason}</Td>
                    <Td className="text-right">
                      {pending ? (
                        isSelf ? <span className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>your own request</span> : (
                          <div className="flex justify-end gap-2">
                            <Button size="sm" onClick={() => run(() => apiPost(`/admin/elevations/${e.id}/approve`, {}), "Elevation approved.", "Approve")}>Approve</Button>
                            <Button size="sm" variant="danger" onClick={() => { setRejectFor(e); setRejectReason(""); }}>Reject</Button>
                          </div>
                        )
                      ) : reviewDue ? (
                        <Button size="sm" variant="ghost" onClick={() => run(() => apiPost(`/admin/elevations/${e.id}/review`, { notes: "Reviewed via console" }), "Break-glass reviewed.", "Review")}>Mark reviewed</Button>
                      ) : "—"}
                    </Td>
                  </tr>
                );
              })}
            </Table>
          )}
        </Panel>
      )}

      {/* Break-glass confirm modal */}
      {confirmBG && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: "rgba(0,0,0,0.6)" }} onClick={() => setConfirmBG(false)}>
          <div className="w-full max-w-md rounded-2xl p-6" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border-strong)" }} onClick={(ev) => ev.stopPropagation()}>
            <div className="mb-2 text-lg font-bold" style={{ color: "var(--c-ink)" }}>Confirm break-glass</div>
            <p className="mb-4 text-sm" style={{ color: "var(--c-ink-2)" }}>
              This immediately elevates you to <span className="font-semibold capitalize">{role.replace(/_/g, " ")}</span> for {mins} minutes.
              An alert fires and a post-use review will be required. Proceed only in a genuine emergency.
            </p>
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="ghost" onClick={() => setConfirmBG(false)}>Cancel</Button>
              <Button size="sm" variant="danger" onClick={() => { setConfirmBG(false); run(() => apiPost("/me/elevations/break-glass", body()).then(() => setReason("")), "Break-glass granted — you are now elevated. Review required.", "Break-glass"); }}>Invoke</Button>
            </div>
          </div>
        </div>
      )}

      {/* Reject reason modal */}
      {rejectFor && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: "rgba(0,0,0,0.6)" }} onClick={() => setRejectFor(null)}>
          <div className="w-full max-w-md rounded-2xl p-6" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border-strong)" }} onClick={(ev) => ev.stopPropagation()}>
            <div className="mb-2 text-lg font-bold" style={{ color: "var(--c-ink)" }}>Reject elevation</div>
            <p className="mb-3 text-sm" style={{ color: "var(--c-ink-2)" }}>{rejectFor.user_email} → <span className="capitalize">{rejectFor.elevated_role.replace(/_/g, " ")}</span></p>
            <textarea value={rejectReason} onChange={(e) => setRejectReason(e.target.value)} rows={2} placeholder="Reason (optional)" className="mb-4 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} />
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="ghost" onClick={() => setRejectFor(null)}>Cancel</Button>
              <Button size="sm" variant="danger" onClick={() => { const id = rejectFor.id; setRejectFor(null); run(() => apiPost(`/admin/elevations/${id}/reject`, { reason: rejectReason }), "Elevation rejected.", "Reject"); }}>Reject</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
