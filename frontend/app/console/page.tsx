"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";

type Me = { email: string; role: string; tenant_id: string };

export default function Dashboard() {
  const [me, setMe] = useState<Me | null>(null);
  const [counts, setCounts] = useState({ alerts: 0, incidents: 0, events: 0 });

  useEffect(() => {
    (async () => {
      try {
        setMe(await apiGet<Me>("/me"));
        const a = await apiGet<{ alerts: unknown[] | null }>("/alerts");
        const i = await apiGet<{ incidents: unknown[] | null }>("/incidents");
        const e = await apiGet<{ events: unknown[] | null }>("/events");
        setCounts({
          alerts: a.alerts?.length ?? 0,
          incidents: i.incidents?.length ?? 0,
          events: e.events?.length ?? 0,
        });
      } catch {
        /* handled by console layout redirect */
      }
    })();
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Dashboard</h1>
      {me && (
        <p className="mt-1 text-sm text-slate-400">
          {me.email} · {me.role} · tenant {me.tenant_id.slice(0, 8)}
        </p>
      )}
      <div className="mt-6 grid grid-cols-3 gap-4">
        <Stat label="Open events" value={counts.events} />
        <Stat label="Alerts" value={counts.alerts} />
        <Stat label="Incidents" value={counts.incidents} />
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-[var(--nirvet-panel)] p-6">
      <div className="text-3xl font-bold text-white">{value}</div>
      <div className="mt-1 text-sm text-slate-400">{label}</div>
    </div>
  );
}
