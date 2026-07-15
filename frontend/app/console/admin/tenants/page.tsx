"use client";

// Platform-admin tenant management (SRS §6.18 / ADMIN-005). Cross-tenant console for the platform super-admin:
// list tenants (GET /admin/tenants), create (POST /admin/tenants), lifecycle status (POST .../status), and the
// governance actions legal-hold / offboard (padmin-gated). All padmin server-side → non-admins get 403, which we
// surface as an access notice rather than a broken page.

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, apiDelete, ApiError, errorText } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, Button, EmptyState } from "@/components/ui";

type Tenant = { id: string; name: string; sector: string; country: string; service_tier: string; isolation_tier: string; status: string; external_ref?: string; created_at: string };

const STATUSES = ["onboarding", "active", "suspended"];
const statusTone: Record<string, "ok" | "warn" | "danger" | "neutral"> = { active: "ok", onboarding: "warn", suspended: "danger", prospect: "neutral" };
const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

export default function AdminTenantsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "forbidden">("loading");
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [show, setShow] = useState(false);
  const [nt, setNt] = useState({ name: "", sector: "", country: "", service_tier: "standard", isolation_tier: "pooled" });
  // F3 — per-tenant onboarding: invite the tenant's first admin. inviteFor = the open tenant row; inviteToken =
  // the one-time link the backend returns (shown once, cannot be retrieved again).
  const [inviteFor, setInviteFor] = useState<string | null>(null);
  const [invite, setInvite] = useState({ email: "", role: "customer_admin" });
  const [inviteToken, setInviteToken] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await apiGet<{ tenants: Tenant[] | null }>("/admin/tenants");
      setTenants(r.tenants ?? []);
      setState("ready");
    } catch (e) {
      setState(e instanceof ApiError && e.status === 403 ? "forbidden" : "ready");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function run(fn: () => Promise<unknown>, ok: string) {
    setMsg(null);
    try {
      await fn();
      setMsg({ tone: "ok", text: ok });
      await load();
    } catch (e) {
      setMsg({ tone: "danger", text: errorText(e, "This requires a platform-admin role.", "Failed.") });
    }
  }

  // Create an invitation for the tenant's admin and surface the one-time link (not reloaded — the token is
  // returned once and never retrievable again, so we keep it in state until the operator dismisses it).
  async function sendInvite(tenantID: string) {
    setMsg(null);
    setInviteToken(null);
    try {
      const r = await apiPost<{ token: string }>(`/admin/tenants/${tenantID}/invitations`, { email: invite.email.trim(), role: invite.role, expires_in_hours: 168 });
      setInviteToken(r.token);
      setMsg({ tone: "ok", text: "Invitation created — share the one-time link below with the tenant admin (valid 7 days)." });
      setInvite({ email: "", role: "customer_admin" });
    } catch (e) {
      setMsg({ tone: "danger", text: errorText(e, "This requires a platform-admin role.", "Could not create invitation.") });
    }
  }

  if (state === "forbidden")
    return <div><PageHeader title="Tenants" /><EmptyState title="Platform-admin only" hint="Tenant management is restricted to the platform super-admin." /></div>;

  return (
    <div>
      <PageHeader title="Tenants" sub="Platform tenant management and lifecycle" actions={<Button size="sm" onClick={() => setShow((s) => !s)}>{show ? "Cancel" : "New tenant"}</Button>} />
      {msg && <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      {show && (
        <Panel title="New tenant" style={{ marginBottom: 24 }}>
          <div className="grid grid-cols-5 gap-2">
            <input value={nt.name} onChange={(e) => setNt({ ...nt, name: e.target.value })} placeholder="Name" className="col-span-2 rounded px-2 py-1.5 text-sm" style={inputStyle} />
            <input value={nt.sector} onChange={(e) => setNt({ ...nt, sector: e.target.value })} placeholder="Sector" className="rounded px-2 py-1.5 text-sm" style={inputStyle} />
            <input value={nt.country} onChange={(e) => setNt({ ...nt, country: e.target.value })} placeholder="Country" className="rounded px-2 py-1.5 text-sm" style={inputStyle} />
            <input value={nt.service_tier} onChange={(e) => setNt({ ...nt, service_tier: e.target.value })} placeholder="service tier" className="rounded px-2 py-1.5 text-sm" style={inputStyle} />
          </div>
          <div className="mt-2 flex items-center gap-2">
            <select value={nt.isolation_tier} onChange={(e) => setNt({ ...nt, isolation_tier: e.target.value })} className="w-72 rounded px-2 py-1.5 text-sm" style={inputStyle} title="Data-isolation tier">
              {["pooled", "dedicated", "sovereign"].map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <Button size="sm" disabled={!nt.name} onClick={() => run(() => apiPost("/admin/tenants", nt).then(() => { setShow(false); setNt({ ...nt, name: "", sector: "", country: "" }); }), "Tenant created.")}>Create</Button>
          </div>
        </Panel>
      )}

      <Panel bodyStyle={{ padding: 0 }}>
        {state === "loading" ? (
          <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>
        ) : tenants.length === 0 ? (
          <div className="p-6"><EmptyState title="No tenants" hint="Create the first tenant to begin." /></div>
        ) : (
          <Table head={<><Th>Tenant</Th><Th>Sector</Th><Th>Tier</Th><Th>Status</Th><Th className="text-right">Lifecycle</Th></>}>
            {tenants.map((t) => (
              <tr key={t.id}>
                <Td className="!text-[color:var(--c-ink)]">
                  {t.name}
                  <div className="mt-0.5 text-[11px]" style={{ color: "var(--c-ink-3)" }}>{t.country || "—"}{t.external_ref ? ` · ${t.external_ref}` : ""}</div>
                </Td>
                <Td className="text-xs capitalize">{t.sector || "—"}</Td>
                <Td className="text-xs">{t.service_tier} · {t.isolation_tier}</Td>
                <Td>
                  <select value={t.status} onChange={(e) => run(() => apiPost(`/admin/tenants/${t.id}/status`, { status: e.target.value }), `${t.name} → ${e.target.value}.`)} className="rounded px-2 py-1 text-xs capitalize" style={{ ...inputStyle, color: statusTone[t.status] === "ok" ? "#6ee7b7" : statusTone[t.status] === "danger" ? "#fca5a5" : "var(--c-ink-2)" }}>
                    {STATUSES.concat(STATUSES.includes(t.status) ? [] : [t.status]).map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                </Td>
                <Td className="text-right">
                  <div className="flex justify-end gap-1.5">
                    <Button size="sm" onClick={() => { setInviteFor(inviteFor === t.id ? null : t.id); setInviteToken(null); }}>{inviteFor === t.id ? "Close" : "Invite admin"}</Button>
                    <Button size="sm" variant="ghost" onClick={() => run(() => apiPost(`/admin/tenants/${t.id}/legal-hold`), "Legal hold set.")}>Hold</Button>
                    <Button size="sm" variant="ghost" onClick={() => run(() => apiDelete(`/admin/tenants/${t.id}/legal-hold`), "Legal hold cleared.")}>Release</Button>
                  </div>
                </Td>
              </tr>
            )).flatMap((row, i) => {
              const t = tenants[i];
              if (inviteFor !== t.id) return [row];
              return [row, (
                <tr key={`${t.id}-onboard`}>
                  <td colSpan={5} style={{ borderTop: "1px solid var(--c-border)", background: "var(--c-surface-2)" }} className="px-4 py-3">
                    <div className="text-[11px] font-semibold uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Onboard {t.name} — invite its admin</div>
                    <div className="mt-2 flex flex-wrap items-end gap-2">
                      <label className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>Admin email
                        <input type="email" value={invite.email} onChange={(e) => setInvite({ ...invite, email: e.target.value })} placeholder="admin@customer.example" className="mt-1 block w-64 rounded-lg px-3 py-1.5 text-sm" style={inputStyle} />
                      </label>
                      <label className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>Role
                        <select value={invite.role} onChange={(e) => setInvite({ ...invite, role: e.target.value })} className="mt-1 block w-40 rounded-lg px-2 py-1.5 text-sm" style={inputStyle}>
                          <option value="customer_admin">customer_admin</option>
                          <option value="customer_viewer">customer_viewer</option>
                        </select>
                      </label>
                      <Button size="sm" disabled={!invite.email.includes("@")} onClick={() => sendInvite(t.id)}>Send invitation</Button>
                    </div>
                    {inviteToken && (
                      <div className="mt-3 rounded-lg p-2.5" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)" }}>
                        <div className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>One-time invitation token (share securely — it cannot be retrieved again):</div>
                        <code className="mt-1 block break-all text-[11px]" style={{ color: "var(--c-primary)" }}>{inviteToken}</code>
                      </div>
                    )}
                  </td>
                </tr>
              )];
            })}
          </Table>
        )}
      </Panel>
      <p className="mt-3 text-[11px]" style={{ color: "var(--c-ink-3)" }}>Offboarding (export + deletion) is a four-eyes workflow — initiate it from the tenant record with a second approver.</p>
    </div>
  );
}
