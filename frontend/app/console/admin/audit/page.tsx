"use client";

// Audit trail (SRS §11.2 GOV-001 / ADMIN-004). Read-only search over the tenant's immutable audit log
// (GET /admin/audit?q=&limit=, ssoAdmin-gated). Every admin/analyst/API/automation/AI mutation lands here;
// this screen searches by action- or target-substring, most-recent-first. 403 → access notice.

import { useCallback, useEffect, useState } from "react";
import { apiGet, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, EmptyState, Button } from "@/components/ui";

type Entry = { actor_email: string; action: string; target: string; request_id: string; at: string };

export default function AuditPage() {
  const [q, setQ] = useState("");
  const [entries, setEntries] = useState<Entry[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "forbidden">("loading");

  const load = useCallback(async (needle: string) => {
    try {
      const r = await apiGet<{ entries: Entry[] | null }>(`/admin/audit?limit=200${needle ? `&q=${encodeURIComponent(needle)}` : ""}`);
      setEntries(r.entries ?? []);
      setState("ready");
    } catch (e) {
      setState(e instanceof ApiError && e.status === 403 ? "forbidden" : "ready");
    }
  }, []);

  useEffect(() => {
    load("");
  }, [load]);

  if (state === "forbidden")
    return <div><PageHeader title="Audit trail" /><EmptyState title="Tenant-admin only" hint="The audit trail is restricted to administrators." /></div>;

  return (
    <div>
      <PageHeader title="Audit trail" sub="Immutable record of every administrative, analyst, API, automation and AI action" />
      <form onSubmit={(e) => { e.preventDefault(); load(q); }} className="mb-4 flex gap-2">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search action or target… (e.g. incident.close, connector, user@)" className="flex-1 rounded-lg px-3 py-2 text-sm outline-none" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" }} />
        <Button type="submit" size="sm">Search</Button>
      </form>
      <Panel bodyStyle={{ padding: 0 }}>
        {state === "loading" ? (
          <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>
        ) : entries.length === 0 ? (
          <div className="p-6"><EmptyState title="No entries" hint="No audit records match this search." /></div>
        ) : (
          <Table head={<><Th>When</Th><Th>Actor</Th><Th>Action</Th><Th>Target</Th></>}>
            {entries.map((e, i) => (
              <tr key={i}>
                <Td className="whitespace-nowrap font-mono text-[11px]">{new Date(e.at).toLocaleString()}</Td>
                <Td className="text-xs">{e.actor_email || "system"}</Td>
                <Td className="!text-[color:var(--c-ink)] font-mono text-xs">{e.action}</Td>
                <Td className="max-w-[280px] truncate font-mono text-[11px]" title={e.target}>{e.target || "—"}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </div>
  );
}
