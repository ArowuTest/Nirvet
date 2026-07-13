"use client";

// Incident board — the case list (SRS §6.8). GET /incidents returns cases with derived SLA-breach flags
// (ack_breached / resolve_breached computed on read). We surface those as an at-a-glance SLA column so the
// analyst sees which cases are overdue without opening each one. Cases are promote-from-alert only, so there
// is no "New incident" action here — that's by design.

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, StatusTag, stageTone, EmptyState } from "@/components/ui";

type Incident = {
  id: string;
  title: string;
  severity: string;
  stage: string;
  created_at: string;
  resolve_due_at?: string;
  ack_breached: boolean;
  resolve_breached: boolean;
  is_major: boolean;
};

const OPEN_STAGES = new Set(["closed", "post_incident_review"]);

export default function IncidentsPage() {
  const [items, setItems] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"open" | "all">("open");

  useEffect(() => {
    (async () => {
      try {
        const res = await apiGet<{ incidents: Incident[] | null }>("/incidents");
        setItems(res.incidents ?? []);
      } catch {
        setItems([]);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const shown = useMemo(
    () => (tab === "open" ? items.filter((i) => !OPEN_STAGES.has(i.stage)) : items),
    [items, tab]
  );

  return (
    <div>
      <PageHeader title="Incidents" sub="Security cases and their lifecycle stage" />

      <div className="mb-4 flex items-center gap-2">
        {(["open", "all"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className="rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition"
            style={
              tab === t
                ? { background: "rgba(14,165,233,0.14)", color: "var(--c-primary)", border: "1px solid var(--c-border-strong)" }
                : { color: "var(--c-ink-2)", border: "1px solid var(--c-border)" }
            }
          >
            {t}
          </button>
        ))}
      </div>

      <Panel bodyStyle={{ padding: 0 }}>
        {loading ? (
          <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading incidents…</div>
        ) : shown.length === 0 ? (
          <div className="p-6">
            <EmptyState title="No incidents" hint={tab === "open" ? "No open cases right now." : "Nothing to show."} />
          </div>
        ) : (
          <Table
            head={
              <>
                <Th>Severity</Th>
                <Th>Incident</Th>
                <Th>Stage</Th>
                <Th>SLA</Th>
                <Th className="text-right">Opened</Th>
              </>
            }
          >
            {shown.map((i) => (
              <tr key={i.id}>
                <Td><SevBadge severity={i.severity} /></Td>
                <Td className="!text-[color:var(--c-ink)]">
                  <Link href={`/console/incidents/${i.id}`} className="font-medium hover:underline">{i.title}</Link>
                  {i.is_major && <span className="ml-2 rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ background: "rgba(239,68,68,0.15)", color: "#fca5a5" }}>MAJOR</span>}
                </Td>
                <Td><StatusTag tone={stageTone(i.stage)}>{i.stage.replace(/_/g, " ")}</StatusTag></Td>
                <Td>
                  {i.ack_breached || i.resolve_breached ? (
                    <StatusTag tone="danger">{i.resolve_breached ? "Resolve overdue" : "Ack overdue"}</StatusTag>
                  ) : (
                    <StatusTag tone="ok">On track</StatusTag>
                  )}
                </Td>
                <Td className="text-right text-xs">{new Date(i.created_at).toLocaleString()}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </div>
  );
}
