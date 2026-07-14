"use client";

// Customer compliance posture (§6.14 / read-model Slice B) — GET /customer/compliance. Per adopted framework:
// coverage score + control-status summary. Control-level internal notes/weights are absent by construction.

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, EmptyState } from "@/components/ui";

type Framework = { key: string; name: string; version: string; score: number; summary: Record<string, number> };

function scoreColor(score: number) {
  if (score >= 80) return "var(--c-ok)";
  if (score >= 50) return "var(--c-warn)";
  return "var(--c-danger)";
}

export default function PortalCompliance() {
  const [items, setItems] = useState<Framework[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiGet<{ frameworks: Framework[] | null }>("/customer/compliance").then((r) => setItems(r.frameworks ?? [])).catch(() => {}).finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <PageHeader title="Compliance" sub="Coverage posture across your adopted frameworks" />
      {loading ? (
        <Panel><div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div></Panel>
      ) : items.length === 0 ? (
        <Panel><EmptyState title="No frameworks enabled" hint="Your operator has not enabled a compliance framework for your organisation yet." /></Panel>
      ) : (
        <div className="grid gap-4" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))" }}>
          {items.map((f) => {
            const total = Object.values(f.summary ?? {}).reduce((a, b) => a + b, 0);
            return (
              <Link key={f.key} href={`/portal/compliance/${encodeURIComponent(f.key)}`} className="group block transition hover:opacity-95">
                <Panel>
                  <div className="mb-4 flex items-start justify-between gap-3">
                    <div>
                      <div className="text-sm font-semibold" style={{ color: "var(--c-ink)" }}>{f.name}</div>
                      <div className="text-xs" style={{ color: "var(--c-ink-3)" }}>v{f.version} · {total} controls</div>
                    </div>
                    <div className="text-right">
                      <div className="text-2xl font-bold" style={{ color: scoreColor(f.score) }}>{f.score}%</div>
                      <div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>coverage</div>
                    </div>
                  </div>
                  <div className="mb-4 h-2 w-full overflow-hidden rounded-full" style={{ background: "var(--c-surface-2)" }}>
                    <div className="h-full rounded-full transition-all" style={{ width: `${Math.max(0, Math.min(100, f.score))}%`, background: scoreColor(f.score) }} />
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {Object.entries(f.summary ?? {}).map(([status, n]) => (
                      <span key={status} className="rounded-lg px-2.5 py-1 text-[11px]" style={{ background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink-2)" }}>
                        <span className="font-semibold" style={{ color: "var(--c-ink)" }}>{n}</span> {status}
                      </span>
                    ))}
                    <span className="ml-auto text-[11px] font-medium transition group-hover:translate-x-0.5" style={{ color: "var(--c-primary)" }}>View controls →</span>
                  </div>
                </Panel>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
