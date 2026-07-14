"use client";

// Customer incident list (§6.3 / UI-002) — GET /customer/incidents (customer read-model projection).

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, StatusTag, stageTone, EmptyState } from "@/components/ui";

type Incident = { incident_id: string; title: string; severity: string; category: string; status: string; created_at: string; ack_breached: boolean; resolve_breached: boolean };

export default function PortalIncidents() {
  const [items, setItems] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiGet<{ incidents: Incident[] | null }>("/customer/incidents").then((r) => setItems(r.incidents ?? [])).catch(() => {}).finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <PageHeader title="Incidents" sub="Security cases affecting your organisation" />
      <Panel bodyStyle={{ padding: 0 }}>
        {loading ? <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div> : items.length === 0 ? (
          <div className="p-6"><EmptyState title="No incidents" hint="No cases have been raised for your estate." /></div>
        ) : (
          <Table head={<><Th>Severity</Th><Th>Incident</Th><Th>Category</Th><Th>Status</Th><Th>SLA</Th><Th className="text-right">Opened</Th></>}>
            {items.map((i) => (
              <tr key={i.incident_id}>
                <Td><SevBadge severity={i.severity} /></Td>
                <Td className="!text-[color:var(--c-ink)]"><Link href={`/portal/incidents/${i.incident_id}`} className="font-medium hover:underline">{i.title}</Link></Td>
                <Td className="text-xs capitalize">{i.category || "—"}</Td>
                <Td><StatusTag tone={stageTone(i.status)}>{i.status.replace(/_/g, " ")}</StatusTag></Td>
                <Td>{i.ack_breached || i.resolve_breached ? <StatusTag tone="danger">Overdue</StatusTag> : <StatusTag tone="ok">On track</StatusTag>}</Td>
                <Td className="text-right text-xs">{new Date(i.created_at).toLocaleDateString()}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </div>
  );
}
