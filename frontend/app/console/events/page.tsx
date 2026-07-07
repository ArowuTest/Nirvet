"use client";

import { useEffect, useState } from "react";
import { apiGet } from "@/lib/api";

type Event = {
  id: string;
  source: string;
  class_name: string;
  severity: string;
  actor_ref: string;
  target_ref: string;
  observed_at: string;
};

export default function EventsPage() {
  const [items, setItems] = useState<Event[]>([]);

  useEffect(() => {
    (async () => {
      const res = await apiGet<{ events: Event[] | null }>("/events");
      setItems(res.events ?? []);
    })();
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Normalized events</h1>
      <div className="mt-6 overflow-hidden rounded-2xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Class</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Actor</th>
              <th className="px-4 py-3">Target</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-6 text-center text-slate-500">
                  No events.
                </td>
              </tr>
            )}
            {items.map((e) => (
              <tr key={e.id} className="border-t border-slate-800">
                <td className="px-4 py-3 text-slate-300">{e.source}</td>
                <td className="px-4 py-3 text-white">{e.class_name}</td>
                <td className="px-4 py-3 text-slate-400">{e.severity}</td>
                <td className="px-4 py-3 text-slate-400">{e.actor_ref}</td>
                <td className="px-4 py-3 text-slate-400">{e.target_ref}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
