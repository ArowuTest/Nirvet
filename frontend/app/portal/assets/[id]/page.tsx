"use client";

// Customer asset detail (read-model Slice B) — GET /customer/assets/{id}. The asset + its blast radius: the open
// vulnerabilities on it and the alerts that targeted it. Every nested item is a customer projection.

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, StatusTag, EmptyState } from "@/components/ui";

type Vuln = { ref: string; cve: string; title: string; severity: string; cvss: number; exploited: boolean; status: string; remediation_due?: string };
type Alert = { alert_id: string; title: string; severity: string; status: string; created_at: string };
type Detail = {
  asset_id: string; ref: string; name: string; kind: string; criticality: string; created_at: string;
  vulnerabilities: Vuln[]; alerts: Alert[];
};

const CRIT_TONE: Record<string, "danger" | "warn" | "info" | "neutral"> = { critical: "danger", high: "warn", medium: "info", low: "neutral" };

export default function PortalAssetDetail() {
  const { id } = useParams<{ id: string }>();
  const [d, setD] = useState<Detail | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");

  useEffect(() => {
    apiGet<{ asset: Detail }>(`/customer/assets/${id}`)
      .then((r) => { setD(r.asset); setState("ready"); })
      .catch(() => setState("error"));
  }, [id]);

  if (state === "loading") return <Panel><div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div></Panel>;
  if (state === "error" || !d) {
    return (
      <div>
        <PageHeader title="Asset" sub="Detail" actions={<Link href="/portal/assets" className="text-sm" style={{ color: "var(--c-primary)" }}>← All assets</Link>} />
        <Panel><EmptyState title="Asset not available" hint="This asset isn't in your inventory." /></Panel>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title={d.name}
        sub={<span className="font-mono text-xs">{d.ref}</span>}
        actions={<Link href="/portal/assets" className="text-sm" style={{ color: "var(--c-primary)" }}>← All assets</Link>}
      />

      <Panel>
        <div className="flex flex-wrap gap-x-10 gap-y-3">
          <div><div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Kind</div><div className="text-sm" style={{ color: "var(--c-ink)" }}>{d.kind}</div></div>
          <div><div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Criticality</div><div className="mt-0.5"><StatusTag tone={CRIT_TONE[d.criticality?.toLowerCase()] ?? "neutral"}>{d.criticality}</StatusTag></div></div>
          <div><div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Open vulnerabilities</div><div className="text-sm font-semibold" style={{ color: "var(--c-ink)" }}>{d.vulnerabilities.length}</div></div>
          <div><div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Alerts targeting</div><div className="text-sm font-semibold" style={{ color: "var(--c-ink)" }}>{d.alerts.length}</div></div>
          <div><div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Added</div><div className="text-sm" style={{ color: "var(--c-ink)" }}>{new Date(d.created_at).toLocaleDateString()}</div></div>
        </div>
      </Panel>

      <div className="mt-6">
        <h3 className="mb-3 text-sm font-semibold" style={{ color: "var(--c-ink-2)" }}>Open vulnerabilities on this asset</h3>
        <Panel bodyStyle={{ padding: 0 }}>
          {d.vulnerabilities.length === 0 ? (
            <div className="p-6"><EmptyState title="No open vulnerabilities" hint="No exposure identified on this asset." /></div>
          ) : (
            <Table head={<><Th>Severity</Th><Th>CVE</Th><Th>Title</Th><Th>CVSS</Th><Th className="text-right">Remediate by</Th></>}>
              {d.vulnerabilities.map((v) => (
                <tr key={`${v.cve}-${v.ref}`}>
                  <Td><div className="flex items-center gap-1.5"><SevBadge severity={v.severity} />{v.exploited && <StatusTag tone="danger">exploited</StatusTag>}</div></Td>
                  <Td className="font-mono text-[11px]">{v.cve || "—"}</Td>
                  <Td className="!text-[color:var(--c-ink)] font-medium">{v.title}</Td>
                  <Td className="text-xs">{v.cvss ? v.cvss.toFixed(1) : "—"}</Td>
                  <Td className="text-right text-xs">{v.remediation_due ? new Date(v.remediation_due).toLocaleDateString() : "—"}</Td>
                </tr>
              ))}
            </Table>
          )}
        </Panel>
      </div>

      <div className="mt-6">
        <h3 className="mb-3 text-sm font-semibold" style={{ color: "var(--c-ink-2)" }}>Alerts targeting this asset</h3>
        <Panel bodyStyle={{ padding: 0 }}>
          {d.alerts.length === 0 ? (
            <div className="p-6"><EmptyState title="No alerts" hint="No detections have targeted this asset." /></div>
          ) : (
            <Table head={<><Th>Severity</Th><Th>Alert</Th><Th>Status</Th><Th className="text-right">Raised</Th></>}>
              {d.alerts.map((a) => (
                <tr key={a.alert_id}>
                  <Td><SevBadge severity={a.severity} /></Td>
                  <Td className="!text-[color:var(--c-ink)] font-medium">{a.title}</Td>
                  <Td><StatusTag tone={a.status === "new" ? "info" : "neutral"}>{a.status}</StatusTag></Td>
                  <Td className="text-right text-xs">{new Date(a.created_at).toLocaleString()}</Td>
                </tr>
              ))}
            </Table>
          )}
        </Panel>
      </div>
    </div>
  );
}
