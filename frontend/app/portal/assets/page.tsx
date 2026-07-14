"use client";

// Customer asset inventory (§6.15 / read-model Slice B) — GET /customer/assets. The customer's own estate:
// canonical ref, name, kind, business criticality. Internal fields (owner assignment, operational tags) are
// absent by construction (CustomerAssetView allowlist).

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, EmptyState, KpiStrip, Kpi } from "@/components/ui";

type Asset = { asset_id: string; ref: string; name: string; kind: string; criticality: string; created_at: string };

const CRIT_TONE: Record<string, "danger" | "warn" | "info" | "neutral"> = {
  critical: "danger",
  high: "warn",
  medium: "info",
  low: "neutral",
};

export default function PortalAssets() {
  const router = useRouter();
  const [items, setItems] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiGet<{ assets: Asset[] | null }>("/customer/assets").then((r) => setItems(r.assets ?? [])).catch(() => {}).finally(() => setLoading(false));
  }, []);

  const crit = items.filter((a) => a.criticality?.toLowerCase() === "critical").length;
  const high = items.filter((a) => a.criticality?.toLowerCase() === "high").length;

  return (
    <div>
      <PageHeader title="Asset inventory" sub="Monitored assets across your estate" />
      <div className="mb-6">
        <KpiStrip>
          <Kpi label="Total assets" value={String(items.length)} sub="under monitoring" />
          <Kpi label="Critical" value={String(crit)} sub="business-critical" />
          <Kpi label="High" value={String(high)} sub="high criticality" />
        </KpiStrip>
      </div>
      <Panel bodyStyle={{ padding: 0 }}>
        {loading ? <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div> : items.length === 0 ? (
          <div className="p-6"><EmptyState title="No assets" hint="No assets have been registered for your estate yet." /></div>
        ) : (
          <Table head={<><Th>Reference</Th><Th>Name</Th><Th>Kind</Th><Th>Criticality</Th><Th className="text-right">Added</Th></>}>
            {items.map((a) => (
              <tr key={a.asset_id} onClick={() => router.push(`/portal/assets/${a.asset_id}`)} className="cursor-pointer transition hover:bg-[color:var(--c-surface-2)]">
                <Td className="font-mono text-[11px]">{a.ref}</Td>
                <Td className="!text-[color:var(--c-ink)] font-medium">{a.name}</Td>
                <Td className="text-xs uppercase tracking-wide">{a.kind}</Td>
                <Td><StatusTag tone={CRIT_TONE[a.criticality?.toLowerCase()] ?? "neutral"}>{a.criticality}</StatusTag></Td>
                <Td className="text-right text-xs">{new Date(a.created_at).toLocaleDateString()}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </div>
  );
}
