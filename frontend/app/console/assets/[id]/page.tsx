"use client";

// Console asset detail (SRS §6.15) — the SOC's full-field view of one asset and its blast radius: the open
// vulnerabilities on it (GET /vulnerabilities?ref=) and the alerts that targeted it (GET /alerts?ref=). Unlike the
// customer portal projection, this shows the internal fields (owner, tags, detection internals) the SOC needs.

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, StatusTag, EmptyState } from "@/components/ui";

type Asset = { id: string; ref: string; name: string; kind: string; criticality: string; owner: string; tags: string[] | null; created_at: string };
type Vuln = { id: string; ref: string; cve: string; title: string; severity: string; cvss: number; exploited: boolean; status: string; remediation_due?: string };
type Alert = { id: string; title: string; severity: string; status: string; actor_ref?: string; mitre?: string; created_at: string };

const critTone: Record<string, "ok" | "warn" | "danger" | "neutral"> = { low: "neutral", medium: "warn", high: "danger", critical: "danger" };
const vulnStatusTone: Record<string, "ok" | "warn" | "danger" | "info" | "neutral"> = { open: "danger", remediating: "warn", accepted: "neutral", resolved: "ok" };

export default function ConsoleAssetDetail() {
  const { id } = useParams<{ id: string }>();
  const [asset, setAsset] = useState<Asset | null>(null);
  const [vulns, setVulns] = useState<Vuln[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");

  useEffect(() => {
    (async () => {
      try {
        const a = await apiGet<Asset>(`/assets/${id}`);
        setAsset(a);
        const [v, al] = await Promise.allSettled([
          apiGet<{ vulnerabilities: Vuln[] | null }>(`/vulnerabilities?ref=${encodeURIComponent(a.ref)}`),
          apiGet<{ alerts: Alert[] | null }>(`/alerts?ref=${encodeURIComponent(a.ref)}`),
        ]);
        if (v.status === "fulfilled") setVulns(v.value.vulnerabilities ?? []);
        if (al.status === "fulfilled") setAlerts(al.value.alerts ?? []);
        setState("ready");
      } catch {
        setState("error");
      }
    })();
  }, [id]);

  if (state === "loading") return <div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>;
  if (state === "error" || !asset) {
    return (
      <div>
        <PageHeader title="Asset" actions={<Link href="/console/assets" className="text-sm" style={{ color: "var(--c-primary)" }}>← Inventory</Link>} />
        <Panel><EmptyState title="Asset not found" hint="This asset isn't in the inventory." /></Panel>
      </div>
    );
  }

  return (
    <div>
      <PageHeader title={asset.name} sub={<span className="font-mono text-xs">{asset.ref}</span>} actions={<div className="flex items-center gap-3"><Link href={`/console/entities?ref=${encodeURIComponent(asset.ref)}`} className="text-sm" style={{ color: "var(--c-primary)" }}>Blast radius →</Link><Link href="/console/assets" className="text-sm" style={{ color: "var(--c-primary)" }}>← Inventory</Link></div>} />

      <Panel>
        <div className="flex flex-wrap gap-x-10 gap-y-3">
          <div><div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Kind</div><div className="text-sm" style={{ color: "var(--c-ink)" }}>{asset.kind}</div></div>
          <div><div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Criticality</div><div className="mt-0.5"><StatusTag tone={critTone[asset.criticality] ?? "neutral"}>{asset.criticality}</StatusTag></div></div>
          <div><div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Owner</div><div className="text-sm" style={{ color: "var(--c-ink)" }}>{asset.owner || "—"}</div></div>
          <div><div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Open vulns</div><div className="text-sm font-semibold" style={{ color: "var(--c-ink)" }}>{vulns.length}</div></div>
          <div><div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Alerts targeting</div><div className="text-sm font-semibold" style={{ color: "var(--c-ink)" }}>{alerts.length}</div></div>
          <div><div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>Tags</div><div className="text-sm" style={{ color: "var(--c-ink)" }}>{asset.tags && asset.tags.length ? asset.tags.join(", ") : "—"}</div></div>
        </div>
      </Panel>

      <div className="mt-6">
        <h3 className="mb-3 text-sm font-semibold" style={{ color: "var(--c-ink-2)" }}>Open vulnerabilities</h3>
        <Panel bodyStyle={{ padding: 0 }}>
          {vulns.length === 0 ? <div className="p-6"><EmptyState title="No open vulnerabilities" hint="No exposure on this asset." /></div> : (
            <Table head={<><Th>Severity</Th><Th>CVE</Th><Th>Title</Th><Th>CVSS</Th><Th>Status</Th><Th className="text-right">Due</Th></>}>
              {vulns.map((v) => (
                <tr key={v.id}>
                  <Td><div className="flex items-center gap-1.5"><SevBadge severity={v.severity} />{v.exploited && <StatusTag tone="danger">exploited</StatusTag>}</div></Td>
                  <Td className="font-mono text-[11px]">{v.cve || "—"}</Td>
                  <Td className="font-medium">{v.title}</Td>
                  <Td className="text-xs">{v.cvss ? v.cvss.toFixed(1) : "—"}</Td>
                  <Td><StatusTag tone={vulnStatusTone[v.status] ?? "neutral"}>{v.status}</StatusTag></Td>
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
          {alerts.length === 0 ? <div className="p-6"><EmptyState title="No alerts" hint="No detections targeted this asset." /></div> : (
            <Table head={<><Th>Severity</Th><Th>Alert</Th><Th>Actor</Th><Th>Status</Th><Th className="text-right">Raised</Th></>}>
              {alerts.map((a) => (
                <tr key={a.id} onClick={() => (window.location.href = `/console/alerts/${a.id}`)} className="cursor-pointer transition hover:bg-[color:var(--c-surface-2)]">
                  <Td><SevBadge severity={a.severity} /></Td>
                  <Td className="font-medium">{a.title}</Td>
                  <Td className="font-mono text-[11px]">{a.actor_ref || "—"}</Td>
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
