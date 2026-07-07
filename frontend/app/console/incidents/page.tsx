"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";

type Incident = {
  id: string;
  title: string;
  severity: string;
  stage: string;
  created_at: string;
};

export default function IncidentsPage() {
  const [items, setItems] = useState<Incident[]>([]);

  useEffect(() => {
    (async () => {
      const res = await apiGet<{ incidents: Incident[] | null }>("/incidents");
      setItems(res.incidents ?? []);
    })();
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Incidents</h1>
      <div className="mt-6 overflow-hidden rounded-2xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-4 py-3">Title</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Stage</th>
              <th className="px-4 py-3">Created</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-6 text-center text-slate-500">
                  No incidents.
                </td>
              </tr>
            )}
            {items.map((i) => (
              <tr key={i.id} className="border-t border-slate-800">
                <td className="px-4 py-3 text-white">{i.title}</td>
                <td className="px-4 py-3 text-slate-400">{i.severity}</td>
                <td className="px-4 py-3 text-slate-400">{i.stage}</td>
                <td className="px-4 py-3 text-slate-500">
                  {new Date(i.created_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
