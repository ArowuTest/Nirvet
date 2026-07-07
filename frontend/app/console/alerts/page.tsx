"use client";

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost } from "@/lib/api";

type Alert = {
  id: string;
  title: string;
  severity: string;
  status: string;
  source: string;
  actor_ref: string;
  target_ref: string;
  created_at: string;
};

const sevColor: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300",
  high: "bg-orange-500/20 text-orange-300",
  medium: "bg-yellow-500/20 text-yellow-300",
  low: "bg-blue-500/20 text-blue-300",
  informational: "bg-slate-500/20 text-slate-300",
};

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [msg, setMsg] = useState<string | null>(null);

  const load = useCallback(async () => {
    const res = await apiGet<{ alerts: Alert[] | null }>("/alerts");
    setAlerts(res.alerts ?? []);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function promote(id: string) {
    setMsg(null);
    try {
      await apiPost(`/alerts/${id}/promote`);
      setMsg("Alert promoted to incident");
      await load();
    } catch {
      setMsg("Promote failed");
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Alert queue</h1>
      {msg && <p className="mt-2 text-sm text-blue-300">{msg}</p>}
      <div className="mt-6 overflow-hidden rounded-2xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Title</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-6 text-center text-slate-500">
                  No alerts.
                </td>
              </tr>
            )}
            {alerts.map((a) => (
              <tr key={a.id} className="border-t border-slate-800">
                <td className="px-4 py-3">
                  <span className={`rounded px-2 py-1 text-xs ${sevColor[a.severity] ?? ""}`}>
                    {a.severity}
                  </span>
                </td>
                <td className="px-4 py-3 text-white">{a.title}</td>
                <td className="px-4 py-3 text-slate-400">{a.source}</td>
                <td className="px-4 py-3 text-slate-400">{a.status}</td>
                <td className="px-4 py-3 text-right">
                  {a.status === "new" && (
                    <button
                      onClick={() => promote(a.id)}
                      className="rounded-lg bg-blue-600 px-3 py-1 text-xs text-white hover:bg-blue-500"
                    >
                      Promote
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
