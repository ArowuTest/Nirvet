"use client";

// Customer SOAR approvals queue (SB3) — GET /customer/soar/approvals + POST .../{id}/approve|reject. When the
// operator has routed destructive-action approval to the customer, pending runs appear here for a customer_admin
// to authorize or cancel. Approving triggers the operator's supervised response — so it is guarded by an explicit
// confirmation modal. Empty (honest) when the tenant's authority mode doesn't involve the customer.

import { useEffect, useState } from "react";
import { apiGet, apiPost, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, EmptyState, Button } from "@/components/ui";

type Approval = { run_id: string; playbook_name: string; incident_id?: string; created_at: string };
type Pending = { kind: "approve" | "reject"; item: Approval } | null;

export default function PortalApprovals() {
  const [items, setItems] = useState<Approval[]>([]);
  const [loading, setLoading] = useState(true);
  const [confirm, setConfirm] = useState<Pending>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "ok" | "err"; text: string } | null>(null);

  function load() {
    setLoading(true);
    apiGet<{ approvals: Approval[] | null }>("/customer/soar/approvals").then((r) => setItems(r.approvals ?? [])).catch(() => {}).finally(() => setLoading(false));
  }
  useEffect(load, []);

  async function decide() {
    if (!confirm) return;
    setBusy(true); setMsg(null);
    try {
      await apiPost(`/customer/soar/approvals/${confirm.item.run_id}/${confirm.kind}`);
      setMsg({ tone: "ok", text: confirm.kind === "approve" ? "Action approved — the response is now authorised." : "Action rejected — nothing was executed." });
      setConfirm(null);
      load();
    } catch (e) {
      const text = e instanceof ApiError ? e.message : "Could not record your decision.";
      setMsg({ tone: "err", text });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageHeader title="Approvals" sub="Security response actions awaiting your authorisation" />

      {msg && (
        <div className="mb-5 rounded-lg px-4 py-3 text-sm" style={{ background: msg.tone === "ok" ? "rgba(16,185,129,0.08)" : "rgba(239,68,68,0.08)", border: `1px solid ${msg.tone === "ok" ? "rgba(16,185,129,0.3)" : "rgba(239,68,68,0.3)"}`, color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>
          {msg.text}
        </div>
      )}

      <Panel bodyStyle={{ padding: 0 }}>
        {loading ? <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div> : items.length === 0 ? (
          <div className="p-6"><EmptyState title="No actions awaiting approval" hint="When a response action needs your authorisation, it will appear here." /></div>
        ) : (
          <Table head={<><Th>Playbook</Th><Th>Incident</Th><Th>Requested</Th><Th className="text-right">Decision</Th></>}>
            {items.map((a) => (
              <tr key={a.run_id}>
                <Td className="!text-[color:var(--c-ink)] font-medium">{a.playbook_name || "Response action"}</Td>
                <Td className="font-mono text-[11px]">{a.incident_id ? a.incident_id.slice(0, 8) : "—"}</Td>
                <Td className="text-xs">{new Date(a.created_at).toLocaleString()}</Td>
                <Td>
                  <div className="flex justify-end gap-2">
                    <button onClick={() => setConfirm({ kind: "reject", item: a })} className="rounded-lg px-3 py-1.5 text-xs font-semibold" style={{ border: "1px solid var(--c-border)", color: "var(--c-ink-2)" }}>Reject</button>
                    <button onClick={() => setConfirm({ kind: "approve", item: a })} className="rounded-lg px-3 py-1.5 text-xs font-semibold text-white" style={{ background: "var(--c-primary)" }}>Approve</button>
                  </div>
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>

      {confirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: "rgba(0,0,0,0.6)" }} onClick={() => !busy && setConfirm(null)}>
          <div className="w-full max-w-md rounded-2xl p-6" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border-strong)" }} onClick={(e) => e.stopPropagation()}>
            <h3 className="text-lg font-bold" style={{ color: "var(--c-ink)" }}>
              {confirm.kind === "approve" ? "Authorise this response action?" : "Reject this response action?"}
            </h3>
            <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--c-ink-2)" }}>
              {confirm.kind === "approve"
                ? <>Approving <span className="font-semibold" style={{ color: "var(--c-ink)" }}>{confirm.item.playbook_name || "this action"}</span> authorises your SOC to execute the containment. This decision is recorded against your account in the audit trail.</>
                : <>Rejecting cancels <span className="font-semibold" style={{ color: "var(--c-ink)" }}>{confirm.item.playbook_name || "this action"}</span>. Nothing is executed. This is recorded in the audit trail.</>}
            </p>
            <div className="mt-6 flex justify-end gap-3">
              <button onClick={() => setConfirm(null)} disabled={busy} className="rounded-lg px-4 py-2 text-sm" style={{ border: "1px solid var(--c-border)", color: "var(--c-ink-2)" }}>Cancel</button>
              <button onClick={decide} disabled={busy} className="rounded-lg px-4 py-2 text-sm font-semibold text-white disabled:opacity-50" style={{ background: confirm.kind === "approve" ? "var(--c-primary)" : "var(--c-danger)" }}>
                {busy ? "Working…" : confirm.kind === "approve" ? "Approve & authorise" : "Reject"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
