"use client";

// Tenant governance settings (SRS §6.1/§6.2). The tenant-admin surface for the operator's own tenant — wired to
// the ssoAdmin routes at /admin/tenants/{me.tenant_id}/…: organisation profile, per-severity SLA targets,
// correlation policy, session policy, the escalation matrix, and authority-to-act policies. All writes are
// ssoAdmin-gated server-side → 403 surfaced. Everything is a real config record (no hardcoding).

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPut, apiPost, apiDelete, getMe, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, Button } from "@/components/ui";

type SLA = { severity: string; ack_seconds: number; resolve_seconds: number };
type Corr = { window_seconds: number; promote_threshold: number; min_alerts_for_promotion: number };
type Session = { access_ttl_seconds: number; ip_allowlist: string[] | null; geo_anomaly_logging: boolean };
type Escalation = { id: string; name: string; role: string; min_severity: string; order_index: number; channel: string; address: string; category?: string };
type Authority = { id: string; action_type: string; mode: string; approver_role: string; business_hours_only: boolean; active: boolean };
type CustomerApproval = { authority: string; bc_customer_authorizable: boolean; link_ttl_seconds: number; customer_approver_ref: string };

const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

function err403(e: unknown, what: string) {
  const forbidden = e instanceof ApiError && e.status === 403;
  return forbidden ? "This requires a tenant-admin role." : e instanceof Error ? e.message : `${what} failed.`;
}

export default function TenantSettingsPage() {
  const [tid, setTid] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);

  const [sla, setSla] = useState<SLA[]>([]);
  const [corr, setCorr] = useState<Corr | null>(null);
  const [sess, setSess] = useState<Session | null>(null);
  const [esc, setEsc] = useState<Escalation[]>([]);
  const [auth, setAuth] = useState<Authority[]>([]);
  const [ca, setCa] = useState<CustomerApproval | null>(null);
  const [newEsc, setNewEsc] = useState({ name: "", role: "soc_manager", min_severity: "high", channel: "email", address: "", order_index: 1 });

  const base = tid ? `/admin/tenants/${tid}` : "";

  const load = useCallback(async (b: string) => {
    const [s, c, se, e, a, ca2] = await Promise.allSettled([
      apiGet<{ policies: SLA[] | null }>(`${b}/sla-policies`),
      apiGet<Corr>(`${b}/correlation-policy`),
      apiGet<Session>(`${b}/session-policy`),
      apiGet<{ contacts: Escalation[] | null }>(`${b}/escalation-contacts`),
      apiGet<{ policies: Authority[] | null }>(`${b}/authority-policies`),
      // Customer-approval routing is a caller's-own-tenant policy (uses p.TenantID, no path param) — flat route.
      apiGet<CustomerApproval>(`/soar/customer-approval`),
    ]);
    // Backend envelopes are exact: ListSLA/ListAuthority → {policies}, ListEscalation → {contacts} (governance_handler.go).
    if (s.status === "fulfilled") setSla(s.value.policies ?? []);
    if (c.status === "fulfilled") setCorr(c.value);
    if (se.status === "fulfilled") setSess(se.value);
    if (e.status === "fulfilled") setEsc(e.value.contacts ?? []);
    if (a.status === "fulfilled") setAuth(a.value.policies ?? []);
    if (ca2.status === "fulfilled") setCa(ca2.value);
  }, []);

  useEffect(() => {
    getMe().then((m) => { setTid(m.tenant_id); load(`/admin/tenants/${m.tenant_id}`); }).catch(() => {});
  }, [load]);

  async function run(fn: () => Promise<unknown>, ok: string, what: string) {
    setMsg(null);
    try {
      await fn();
      setMsg({ tone: "ok", text: ok });
      if (base) await load(base);
    } catch (e) {
      setMsg({ tone: "danger", text: err403(e, what) });
    }
  }

  const setSlaRow = (i: number, patch: Partial<SLA>) => setSla((r) => r.map((x, idx) => (idx === i ? { ...x, ...patch } : x)));

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <PageHeader title="Tenant governance" sub="SLA, correlation, session, escalation and authority-to-act policy for your tenant" />
      {msg && <p className="text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      <Panel title="SLA targets" sub="Per-severity acknowledge and resolve deadlines (minutes)">
        {sla.length === 0 ? <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>No SLA policies configured.</p> : (
          <Table head={<><Th>Severity</Th><Th>Ack (min)</Th><Th>Resolve (min)</Th><Th className="text-right"></Th></>}>
            {sla.map((p, i) => (
              <tr key={p.severity}>
                <Td className="capitalize">{p.severity}</Td>
                <Td><input type="number" value={Math.round(p.ack_seconds / 60)} onChange={(e) => setSlaRow(i, { ack_seconds: Number(e.target.value) * 60 })} className="w-24 rounded px-2 py-1 text-sm" style={inputStyle} /></Td>
                <Td><input type="number" value={Math.round(p.resolve_seconds / 60)} onChange={(e) => setSlaRow(i, { resolve_seconds: Number(e.target.value) * 60 })} className="w-24 rounded px-2 py-1 text-sm" style={inputStyle} /></Td>
                <Td className="text-right"><Button size="sm" variant="ghost" onClick={() => run(() => apiPut(`${base}/sla-policies`, { severity: p.severity, ack_seconds: p.ack_seconds, resolve_seconds: p.resolve_seconds }), `${p.severity} SLA saved.`, "Save")}>Save</Button></Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>

      {corr && (
        <Panel title="Correlation policy" sub="How alerts group into incidents (COR-003)">
          <div className="grid grid-cols-3 gap-4">
            <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>Window (min)
              <input type="number" value={Math.round(corr.window_seconds / 60)} onChange={(e) => setCorr({ ...corr, window_seconds: Number(e.target.value) * 60 })} className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} /></label>
            <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>Promote threshold (risk)
              <input type="number" value={corr.promote_threshold} onChange={(e) => setCorr({ ...corr, promote_threshold: Number(e.target.value) })} className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} /></label>
            <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>Min alerts
              <input type="number" value={corr.min_alerts_for_promotion} onChange={(e) => setCorr({ ...corr, min_alerts_for_promotion: Number(e.target.value) })} className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} /></label>
          </div>
          <Button className="mt-3" size="sm" onClick={() => run(() => apiPut(`${base}/correlation-policy`, corr), "Correlation policy saved.", "Save")}>Save</Button>
        </Panel>
      )}

      {sess && (
        <Panel title="Session policy" sub="Access token lifetime, IP allowlist and geo-anomaly logging (IAM-007)">
          <div className="space-y-3">
            <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>Access token TTL (minutes)
              <input type="number" value={Math.round(sess.access_ttl_seconds / 60)} onChange={(e) => setSess({ ...sess, access_ttl_seconds: Number(e.target.value) * 60 })} className="mt-1 w-40 rounded-lg px-3 py-2 text-sm" style={inputStyle} /></label>
            <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>IP allowlist (comma-separated CIDRs; blank = any)
              <input value={(sess.ip_allowlist ?? []).join(", ")} onChange={(e) => setSess({ ...sess, ip_allowlist: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} placeholder="203.0.113.0/24, …" className="mt-1 w-full rounded-lg px-3 py-2 font-mono text-sm" style={inputStyle} /></label>
            <label className="flex items-center gap-2 text-[12px]" style={{ color: "var(--c-ink-2)" }}>
              <input type="checkbox" checked={sess.geo_anomaly_logging} onChange={(e) => setSess({ ...sess, geo_anomaly_logging: e.target.checked })} /> Log geo-anomalies
            </label>
          </div>
          <Button className="mt-3" size="sm" onClick={() => run(() => apiPut(`${base}/session-policy`, { access_ttl_seconds: sess.access_ttl_seconds, ip_allowlist: sess.ip_allowlist ?? [], geo_anomaly_logging: sess.geo_anomaly_logging }), "Session policy saved.", "Save")}>Save</Button>
        </Panel>
      )}

      <Panel title="Escalation matrix" sub="Who is notified, by severity and channel (TEN-006 / COMM-002)">
        {esc.length > 0 && (
          <Table head={<><Th>Order</Th><Th>Name</Th><Th>Role</Th><Th>Min severity</Th><Th>Channel</Th><Th className="text-right"></Th></>}>
            {esc.map((c) => (
              <tr key={c.id}>
                <Td>{c.order_index}</Td><Td className="!text-[color:var(--c-ink)]">{c.name}</Td><Td className="capitalize">{c.role.replace(/_/g, " ")}</Td>
                <Td><StatusTag tone="neutral">{c.min_severity}</StatusTag></Td>
                <Td className="text-xs">{c.channel} · {c.address}</Td>
                <Td className="text-right"><Button size="sm" variant="danger" onClick={() => run(() => apiDelete(`${base}/escalation-contacts/${c.id}`), "Contact removed.", "Remove")}>✕</Button></Td>
              </tr>
            ))}
          </Table>
        )}
        <div className="mt-3 grid grid-cols-6 gap-2">
          <input value={newEsc.name} onChange={(e) => setNewEsc({ ...newEsc, name: e.target.value })} placeholder="Name" className="col-span-2 rounded px-2 py-1.5 text-sm" style={inputStyle} />
          <input value={newEsc.role} onChange={(e) => setNewEsc({ ...newEsc, role: e.target.value })} placeholder="role" className="rounded px-2 py-1.5 text-sm" style={inputStyle} />
          <select value={newEsc.min_severity} onChange={(e) => setNewEsc({ ...newEsc, min_severity: e.target.value })} className="rounded px-2 py-1.5 text-sm capitalize" style={inputStyle}>{SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}</select>
          <input value={newEsc.address} onChange={(e) => setNewEsc({ ...newEsc, address: e.target.value })} placeholder="email/number" className="rounded px-2 py-1.5 text-sm" style={inputStyle} />
          <Button size="sm" disabled={!newEsc.name || !newEsc.address} onClick={() => run(() => apiPost(`${base}/escalation-contacts`, newEsc).then(() => setNewEsc({ ...newEsc, name: "", address: "" })), "Contact added.", "Add")}>Add</Button>
        </div>
      </Panel>

      <Panel title="Authority to act" sub="Per-action automation policy (SOAR-003) — mode + approver">
        {auth.length === 0 ? <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>No authority policies configured — destructive actions require explicit approval by default.</p> : (
          <Table head={<><Th>Action</Th><Th>Mode</Th><Th>Approver</Th><Th>Hours</Th><Th className="text-right"></Th></>}>
            {auth.map((p, i) => (
              <tr key={p.id}>
                <Td className="!text-[color:var(--c-ink)] font-mono text-xs">{p.action_type}</Td>
                <Td>
                  <select value={p.mode} onChange={(e) => setAuth((a) => a.map((x, idx) => (idx === i ? { ...x, mode: e.target.value } : x)))} className="rounded px-2 py-1 text-xs" style={inputStyle}>
                    {["observe", "approval", "pre_authorized", "emergency"].map((m) => <option key={m} value={m}>{m.replace(/_/g, " ")}</option>)}
                  </select>
                </Td>
                <Td className="text-xs capitalize">{p.approver_role.replace(/_/g, " ")}</Td>
                <Td>{p.business_hours_only ? <StatusTag tone="warn">business hrs</StatusTag> : <StatusTag tone="neutral">any</StatusTag>}</Td>
                <Td className="text-right"><Button size="sm" variant="ghost" onClick={() => run(() => apiPut(`${base}/authority-policies`, { action_type: p.action_type, mode: p.mode, approver_role: p.approver_role, business_hours_only: p.business_hours_only }), `${p.action_type} policy saved.`, "Save")}>Save</Button></Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>

      <Panel title="Customer approval routing" sub="Who authorises destructive SOAR steps for this tenant (#188). Routes runs to the customer approvals queue.">
        {ca === null ? <p className="text-[12px]" style={{ color: "var(--c-ink-3)" }}>Loading…</p> : (
          <div className="grid gap-4 md:grid-cols-2">
            <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Authority mode
              <select value={ca.authority} onChange={(e) => setCa({ ...ca, authority: e.target.value })} className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle}>
                <option value="platform_analyst">Platform analyst — internal SOC approves (no customer routing)</option>
                <option value="customer_approver">Customer approver — the customer authorises</option>
                <option value="both_required">Both required — customer + internal rank</option>
              </select>
              <span className="mt-1 block text-[11px]" style={{ color: "var(--c-ink-3)" }}>
                {ca.authority === "platform_analyst" ? "Runs never route to the customer queue — internal approval only." : "Destructive runs will surface in the customer's approvals queue."}
              </span>
            </label>
            <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Approval link TTL (minutes)
              <input type="number" min={5} max={1440} value={Math.round(ca.link_ttl_seconds / 60)} onChange={(e) => setCa({ ...ca, link_ttl_seconds: Math.max(300, Math.min(86400, Number(e.target.value) * 60)) })} className="mt-1 w-40 rounded-lg px-3 py-2 text-sm" style={inputStyle} />
              <span className="mt-1 block text-[11px]" style={{ color: "var(--c-ink-3)" }}>Single-use approval link validity (5–1440 min).</span>
            </label>
            <label className="text-xs" style={{ color: "var(--c-ink-2)" }}>Customer approver ref
              <input value={ca.customer_approver_ref} onChange={(e) => setCa({ ...ca, customer_approver_ref: e.target.value })} placeholder="customer_admin@… or role ref" className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} disabled={ca.authority === "platform_analyst"} />
              <span className="mt-1 block text-[11px]" style={{ color: "var(--c-ink-3)" }}>Identity the customer-side link is issued to.</span>
            </label>
            <label className="flex items-center gap-2 self-end pb-2 text-xs" style={{ color: "var(--c-ink-2)" }}>
              <input type="checkbox" checked={ca.bc_customer_authorizable} onChange={(e) => setCa({ ...ca, bc_customer_authorizable: e.target.checked })} disabled={ca.authority === "platform_analyst"} />
              Customer may authorise business-continuity (high-blast) steps
            </label>
            <div className="md:col-span-2">
              <Button size="sm" onClick={() => run(() => apiPut(`/soar/customer-approval`, { authority: ca.authority, bc_customer_authorizable: ca.bc_customer_authorizable, link_ttl_seconds: ca.link_ttl_seconds, customer_approver_ref: ca.customer_approver_ref }), "Customer approval routing saved.", "Save")}>Save routing</Button>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}
