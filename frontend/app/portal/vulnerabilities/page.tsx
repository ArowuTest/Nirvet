"use client";

// Customer vulnerability exposure (§6.15 slice 2 / read-model Slice B) — GET /customer/vulnerabilities. Exposure
// on the customer's own estate: CVE, affected asset, severity/CVSS, known-exploited flag, remediation timeline.

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, StatusTag, EmptyState, KpiStrip, Kpi } from "@/components/ui";

type Vuln = {
  ref: string;
  cve: string;
  title: string;
  severity: string;
  cvss: number;
  exploited: boolean;
  status: string;
  remediation_due?: string;
  created_at: string;
};
type Asset = { asset_id: string; ref: string };

// AssetRef renders an affected-asset reference, linking to the asset detail when we can resolve it.
function AssetRef({ refStr, map }: { refStr: string; map: Record<string, string> }) {
  if (!refStr) return <>—</>;
  const id = map[refStr];
  if (!id) return <span className="font-mono text-[11px]">{refStr}</span>;
  return <Link href={`/portal/assets/${id}`} className="font-mono text-[11px]" style={{ color: "var(--c-primary)" }}>{refStr}</Link>;
}

export default function PortalVulnerabilities() {
  const [items, setItems] = useState<Vuln[]>([]);
  const [assetMap, setAssetMap] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiGet<{ vulnerabilities: Vuln[] | null }>("/customer/vulnerabilities").then((r) => setItems(r.vulnerabilities ?? [])).catch(() => {}).finally(() => setLoading(false));
    apiGet<{ assets: Asset[] | null }>("/customer/assets").then((r) => {
      const m: Record<string, string> = {};
      (r.assets ?? []).forEach((a) => { m[a.ref] = a.asset_id; });
      setAssetMap(m);
    }).catch(() => {});
  }, []);

  const critHigh = items.filter((v) => ["critical", "high"].includes(v.severity?.toLowerCase())).length;
  const exploited = items.filter((v) => v.exploited).length;
  const open = items.filter((v) => v.status?.toLowerCase() === "open").length;

  return (
    <div>
      <PageHeader title="Vulnerabilities" sub="Exposure identified across your estate" />
      <div className="mb-6">
        <KpiStrip>
          <Kpi label="Open" value={String(open)} sub="awaiting remediation" />
          <Kpi label="Critical + High" value={String(critHigh)} sub="prioritised" />
          <Kpi label="Known-exploited" value={String(exploited)} sub="active exploitation" />
        </KpiStrip>
      </div>
      <Panel bodyStyle={{ padding: 0 }}>
        {loading ? <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div> : items.length === 0 ? (
          <div className="p-6"><EmptyState title="No open vulnerabilities" hint="No exposure has been identified on your estate." /></div>
        ) : (
          <Table head={<><Th>Severity</Th><Th>CVE</Th><Th>Title</Th><Th>Affected asset</Th><Th>CVSS</Th><Th>Status</Th><Th className="text-right">Remediate by</Th></>}>
            {items.map((v) => (
              <tr key={`${v.cve}-${v.ref}`}>
                <Td>
                  <div className="flex items-center gap-1.5">
                    <SevBadge severity={v.severity} />
                    {v.exploited && <StatusTag tone="danger">exploited</StatusTag>}
                  </div>
                </Td>
                <Td className="font-mono text-[11px]">{v.cve || "—"}</Td>
                <Td className="!text-[color:var(--c-ink)] font-medium">{v.title}</Td>
                <Td><AssetRef refStr={v.ref} map={assetMap} /></Td>
                <Td className="text-xs">{v.cvss ? v.cvss.toFixed(1) : "—"}</Td>
                <Td><StatusTag tone={v.status?.toLowerCase() === "open" ? "warn" : "ok"}>{v.status}</StatusTag></Td>
                <Td className="text-right text-xs">{v.remediation_due ? new Date(v.remediation_due).toLocaleDateString() : "—"}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </div>
  );
}
