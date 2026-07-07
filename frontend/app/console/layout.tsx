"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getToken, clearToken } from "@/lib/api";

const nav = [
  { href: "/console", label: "Dashboard" },
  { href: "/console/alerts", label: "Alerts" },
  { href: "/console/incidents", label: "Incidents" },
  { href: "/console/events", label: "Events" },
];

export default function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (!getToken()) router.replace("/login");
    else setReady(true);
  }, [router]);

  if (!ready) return null;

  return (
    <div className="flex min-h-screen">
      <aside className="w-56 shrink-0 border-r border-slate-800 bg-[var(--nirvet-panel)] p-4">
        <div className="mb-6">
          <div className="text-lg font-bold text-white">Nirvet</div>
          <div className="text-xs text-blue-300">SOC Console</div>
        </div>
        <nav className="space-y-1">
          {nav.map((n) => (
            <Link
              key={n.href}
              href={n.href}
              className="block rounded-lg px-3 py-2 text-sm text-slate-300 hover:bg-slate-800 hover:text-white"
            >
              {n.label}
            </Link>
          ))}
        </nav>
        <button
          onClick={() => {
            clearToken();
            router.replace("/login");
          }}
          className="mt-8 w-full rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:bg-slate-800"
        >
          Sign out
        </button>
      </aside>
      <main className="flex-1 p-8">{children}</main>
    </div>
  );
}
