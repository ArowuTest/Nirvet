"use client";

// IAM administration (SRS §6.2 / IAM-001/008/009). One screen over the tenant's access-review
// (GET /admin/tenants/{id}/access-review → users + service_accounts + pending_invitations), with the lifecycle
// actions: reset-password / disable / reactivate a user, create+revoke invitations, create service accounts and
// mint/revoke their API keys (secret shown once). All ssoAdmin-gated server-side → 403 surfaced.

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, apiDelete, getMe, errorText } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, Button } from "@/components/ui";
import { RoleGate } from "@/components/role-gate";

type Role = string;
type User = { id: string; email: string; role: Role; status: string; mfa_enabled: boolean; last_login_at?: string };
type ServiceAccount = { id: string; name: string; role: Role; active: boolean };
type Invitation = { id: string; email: string; role: Role; expires_at: string; accepted_at?: string };
type APIKey = { id: string; prefix: string; label: string; role: Role; expires_at?: string; last_used_at?: string; revoked_at?: string };
type Review = { users: User[] | null; service_accounts: ServiceAccount[] | null; pending_invitations: Invitation[] | null };

// Grantable roles — exactly auth.knownRoles minus platform_admin (non-grantable). Invalid values 400 at the backend.
const ROLES = ["soc_manager", "analyst_t1", "analyst_t2", "analyst_t3", "detection_engineer", "customer_admin", "customer_viewer"];
const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

export default function Page() {
  // Identity/IAM management is platform-admin only (ssoAdmin routes → platform_admin in the console). Gate the
  // whole page so a non-admin who navigates straight here sees a denial, not the Invite/Create controls (BUG-2).
  return (
    <RoleGate allow={["platform_admin"]} title="Identity & access">
      <IamAdminPage />
    </RoleGate>
  );
}

function IamAdminPage() {
  const [tid, setTid] = useState<string | null>(null);
  const [rev, setRev] = useState<Review>({ users: [], service_accounts: [], pending_invitations: [] });
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [keys, setKeys] = useState<Record<string, APIKey[]>>({});
  const [inv, setInv] = useState({ email: "", role: "analyst_t1" });
  const [sa, setSa] = useState({ name: "", role: "analyst_t1" });
  const [disableU, setDisableU] = useState<User | null>(null); // confirm target for the destructive kill-switch

  const base = tid ? `/admin/tenants/${tid}` : "";

  const load = useCallback(async (b: string) => {
    try {
      setRev(await apiGet<Review>(`${b}/access-review`));
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    getMe().then((m) => { setTid(m.tenant_id); load(`/admin/tenants/${m.tenant_id}`); }).catch(() => {});
  }, [load]);

  async function run(fn: () => Promise<unknown>, ok: string) {
    setMsg(null);
    try {
      await fn();
      setMsg({ tone: "ok", text: ok });
      if (base) await load(base);
    } catch (e) {
      setMsg({ tone: "danger", text: errorText(e, "This requires a tenant-admin role.", "Failed.") });
    }
  }

  async function loadKeys(said: string) {
    try {
      const r = await apiGet<{ keys: APIKey[] | null }>(`${base}/service-accounts/${said}/keys`);
      setKeys((k) => ({ ...k, [said]: r.keys ?? [] }));
    } catch {
      setKeys((k) => ({ ...k, [said]: [] }));
    }
  }
  async function mintKey(said: string) {
    setMsg(null);
    setSecret(null);
    try {
      const r = await apiPost<{ api_key?: unknown; key?: string }>(`${base}/service-accounts/${said}/keys`, { label: "console-issued" });
      setSecret(r.key ?? "(created — copy from the API response)"); // backend returns the one-time secret under `key`
      await loadKeys(said);
    } catch (e) {
      setMsg({ tone: "danger", text: errorText(e, "Requires tenant-admin.", "Could not create key.") });
    }
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <PageHeader title="Identity & access" sub="Users, invitations and service accounts for your tenant" />
      {msg && <p className="text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}
      {secret && (
        <div className="rounded-lg p-3 text-[13px]" style={{ background: "rgba(16,185,129,0.08)", border: "1px solid var(--c-border)" }}>
          <span style={{ color: "var(--c-ok)" }}>API key created — shown once:</span> <span className="font-mono" style={{ color: "var(--c-ink)" }}>{secret}</span>
        </div>
      )}

      <Panel title="Users" sub="Access review (IAM-009) — role, status, MFA, last login">
        <Table head={<><Th>User</Th><Th>Role</Th><Th>MFA</Th><Th>Status</Th><Th>Last login</Th><Th className="text-right">Actions</Th></>}>
          {(rev.users ?? []).map((u) => (
            <tr key={u.id}>
              <Td className="!text-[color:var(--c-ink)]">{u.email}</Td>
              <Td className="text-xs capitalize">{u.role.replace(/_/g, " ")}</Td>
              <Td>{u.mfa_enabled ? <StatusTag tone="ok">on</StatusTag> : <StatusTag tone="warn">off</StatusTag>}</Td>
              <Td><StatusTag tone={u.status === "active" ? "ok" : "danger"}>{u.status}</StatusTag></Td>
              <Td className="text-xs">{u.last_login_at ? new Date(u.last_login_at).toLocaleDateString() : "never"}</Td>
              <Td className="text-right">
                <div className="flex justify-end gap-1.5">
                  <Button size="sm" variant="ghost" onClick={() => run(() => apiPost(`${base}/users/${u.id}/reset-password`), "Reset link issued.")}>Reset</Button>
                  {u.status === "active" ? (
                    <Button size="sm" variant="danger" onClick={() => setDisableU(u)}>Disable</Button>
                  ) : (
                    <Button size="sm" variant="ghost" onClick={() => run(() => apiPost(`${base}/users/${u.id}/reactivate`), "User reactivated.")}>Reactivate</Button>
                  )}
                </div>
              </Td>
            </tr>
          ))}
        </Table>
      </Panel>

      <Panel title="Invitations" sub="Invite a user by email + role (IAM-001)">
        {(rev.pending_invitations ?? []).length > 0 && (
          <Table head={<><Th>Email</Th><Th>Role</Th><Th>Expires</Th><Th className="text-right"></Th></>}>
            {(rev.pending_invitations ?? []).map((i) => (
              <tr key={i.id}>
                <Td className="!text-[color:var(--c-ink)]">{i.email}</Td>
                <Td className="text-xs capitalize">{i.role.replace(/_/g, " ")}</Td>
                <Td className="text-xs">{new Date(i.expires_at).toLocaleDateString()}</Td>
                <Td className="text-right"><Button size="sm" variant="danger" onClick={() => run(() => apiDelete(`${base}/invitations/${i.id}`), "Invitation revoked.")}>Revoke</Button></Td>
              </tr>
            ))}
          </Table>
        )}
        <div className="mt-3 flex gap-2">
          <input value={inv.email} onChange={(e) => setInv({ ...inv, email: e.target.value })} placeholder="email@org.com" className="flex-1 rounded-lg px-3 py-1.5 text-sm outline-none" style={inputStyle} />
          <select value={inv.role} onChange={(e) => setInv({ ...inv, role: e.target.value })} className="rounded-lg px-2.5 py-1.5 text-sm capitalize" style={inputStyle}>{ROLES.map((r) => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}</select>
          <Button size="sm" disabled={!inv.email} onClick={() => run(() => apiPost(`${base}/invitations`, inv).then(() => setInv({ ...inv, email: "" })), "Invitation sent.")}>Invite</Button>
        </div>
      </Panel>

      <Panel title="Service accounts" sub="Machine identities + API keys (IAM-005)">
        <ul className="space-y-2">
          {(rev.service_accounts ?? []).map((s) => (
            <li key={s.id} className="rounded-lg p-3" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)" }}>
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium" style={{ color: "var(--c-ink)" }}>{s.name}</span>
                <span className="text-xs capitalize" style={{ color: "var(--c-ink-3)" }}>{s.role.replace(/_/g, " ")}</span>
                <StatusTag tone={s.active ? "ok" : "neutral"}>{s.active ? "active" : "inactive"}</StatusTag>
                <div className="ml-auto flex gap-1.5">
                  <Button size="sm" variant="ghost" onClick={() => loadKeys(s.id)}>Keys</Button>
                  <Button size="sm" onClick={() => mintKey(s.id)}>+ Key</Button>
                </div>
              </div>
              {keys[s.id] && (
                <ul className="mt-2 space-y-1">
                  {keys[s.id].length === 0 ? <li className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>No keys.</li> : keys[s.id].map((k) => (
                    <li key={k.id} className="flex items-center gap-2 text-[11px]" style={{ color: "var(--c-ink-2)" }}>
                      <span className="font-mono">{k.prefix}…</span>
                      <span>{k.label}</span>
                      {k.revoked_at ? <StatusTag tone="danger">revoked</StatusTag> : <StatusTag tone="ok">active</StatusTag>}
                      {!k.revoked_at && <button onClick={() => run(() => apiDelete(`${base}/api-keys/${k.id}`), "Key revoked.")} className="ml-auto" style={{ color: "var(--c-danger)" }}>revoke</button>}
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
        <div className="mt-3 flex gap-2">
          <input value={sa.name} onChange={(e) => setSa({ ...sa, name: e.target.value })} placeholder="Service account name" className="flex-1 rounded-lg px-3 py-1.5 text-sm outline-none" style={inputStyle} />
          <select value={sa.role} onChange={(e) => setSa({ ...sa, role: e.target.value })} className="rounded-lg px-2 py-1.5 text-sm outline-none" style={inputStyle} title="Role granted to keys issued for this service account">
            {ROLES.map((r) => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}
          </select>
          <Button size="sm" disabled={!sa.name} onClick={() => run(() => apiPost(`${base}/service-accounts`, sa).then(() => setSa({ ...sa, name: "" })), "Service account created.")}>Create</Button>
        </div>
      </Panel>

      {disableU && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: "rgba(0,0,0,0.6)" }} onClick={() => setDisableU(null)}>
          <div className="w-full max-w-md rounded-2xl p-6" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border-strong)" }} onClick={(ev) => ev.stopPropagation()}>
            <div className="mb-2 text-lg font-bold" style={{ color: "var(--c-ink)" }}>Disable user</div>
            <p className="mb-4 text-sm" style={{ color: "var(--c-ink-2)" }}>
              Disabling <span className="font-semibold">{disableU.email}</span> immediately revokes their live sessions on every device and
              blocks sign-in until reactivated. Continue?
            </p>
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="ghost" onClick={() => setDisableU(null)}>Cancel</Button>
              <Button size="sm" variant="danger" onClick={() => { const id = disableU.id; setDisableU(null); run(() => apiPost(`${base}/users/${id}/disable`), "User disabled — live sessions revoked."); }}>Disable &amp; revoke sessions</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
