"use client";

// Customer alert list (§6.3) — GET /customer/alerts (customer read-model projection). What/how-bad/status +
// the customer's own affected asset; detection internals are absent by construction.

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, StatusTag, EmptyState } from "@/components/ui";

type Alert = { alert_id: string; title: string; severity: string; status: string; affected_asset?: string; created_at: string };
type Asset = { asset_id: string; ref: string };

function AssetRef({ refStr, map }: { refStr?: string; map: Record<string, string> }) {
  if (!refStr) return <>—</>;
  const id = map[refStr];
  if (!id) return <span className="font-mono text-[11px]">{refStr}</span>;
  return <Link href={`/portal/assets/${id}`} className="font-mono text-[11px]" style={{ color: "var(--c-primary)" }}>{refStr}</Link>;
}

export default function PortalAlerts() {
  const [items, setItems] = useState<Alert[]>([]);
  const [assetMap, setAssetMap] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiGet<{ alerts: Alert[] | null }>("/customer/alerts").then((r) => setItems(r.alerts ?? [])).catch(() => {}).finally(() => setLoading(false));
    apiGet<{ assets: Asset[] | null }>("/customer/assets").then((r) => {
      const m: Record<string, string> = {};
      (r.assets ?? []).forEach((a) => { m[a.ref] = a.asset_id; });
      setAssetMap(m);
    }).catch(() => {});
  }, []);

  return (
    <div>
      <PageHeader title="Alerts" sub="Detections raised against your estate" />
      <Panel bodyStyle={{ padding: 0 }}>
        {loading ? <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div> : items.length === 0 ? (
          <div className="p-6"><EmptyState title="No alerts" hint="No detections have fired for your estate." /></div>
        ) : (
          <Table head={<><Th>Severity</Th><Th>Alert</Th><Th>Affected asset</Th><Th>Status</Th><Th className="text-right">Raised</Th></>}>
            {items.map((a) => (
              <tr key={a.alert_id}>
                <Td><SevBadge severity={a.severity} /></Td>
                <Td className="!text-[color:var(--c-ink)] font-medium">{a.title}</Td>
                <Td><AssetRef refStr={a.affected_asset} map={assetMap} /></Td>
                <Td><StatusTag tone={a.status === "new" ? "info" : "neutral"}>{a.status}</StatusTag></Td>
                <Td className="text-right text-xs">{new Date(a.created_at).toLocaleString()}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </div>
  );
}
