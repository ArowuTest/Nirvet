"use client";

// Customer compliance drill-down (read-model Slice B) — GET /customer/compliance/{key}. The function→control
// tree with per-control status + what each control requires, so a customer can see EXACTLY which controls are
// the gaps. Internal assessment metadata (source/note/evidence) is absent by construction.

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { PageHeader, Panel, StatusTag, EmptyState } from "@/components/ui";

type Control = { control_ref: string; title: string; description: string; status: string };
type Fn = { control_ref: string; title: string; description: string; status: string; controls: Control[] };
type Detail = { key: string; name: string; version: string; score: number; summary: Record<string, number>; functions: Fn[] };

const STATUS_TONE: Record<string, "ok" | "warn" | "danger" | "neutral"> = {
  met: "ok",
  partial: "warn",
  gap: "danger",
  not_applicable: "neutral",
};

function statusLabel(s: string) {
  return s === "not_applicable" ? "N/A" : s;
}

export default function PortalComplianceDetail() {
  const { key } = useParams<{ key: string }>();
  const [d, setD] = useState<Detail | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");

  useEffect(() => {
    apiGet<{ framework: Detail }>(`/customer/compliance/${encodeURIComponent(key)}`)
      .then((r) => { setD(r.framework); setState("ready"); })
      .catch(() => setState("error"));
  }, [key]);

  if (state === "loading") return <Panel><div className="text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div></Panel>;
  if (state === "error" || !d) {
    return (
      <div>
        <PageHeader title="Compliance" sub="Framework detail" actions={<Link href="/portal/compliance" className="text-sm" style={{ color: "var(--c-primary)" }}>← All frameworks</Link>} />
        <Panel><EmptyState title="Framework not available" hint="This framework isn't enabled for your organisation." /></Panel>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title={d.name}
        sub={`v${d.version} · overall coverage ${d.score}%`}
        actions={<Link href="/portal/compliance" className="text-sm" style={{ color: "var(--c-primary)" }}>← All frameworks</Link>}
      />

      <div className="mb-6 flex flex-wrap gap-2">
        {Object.entries(d.summary ?? {}).map(([status, n]) => (
          <StatusTag key={status} tone={STATUS_TONE[status] ?? "neutral"}>{n} {statusLabel(status)}</StatusTag>
        ))}
      </div>

      {(!d.functions || d.functions.length === 0) ? (
        <Panel><EmptyState title="No controls assessed" hint="Controls for this framework have not been assessed yet." /></Panel>
      ) : (
        <div className="flex flex-col gap-4">
          {d.functions.map((fn) => (
            <Panel key={fn.control_ref}>
              <div className="mb-1 flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px]" style={{ color: "var(--c-ink-3)" }}>{fn.control_ref}</span>
                  <span className="text-sm font-semibold" style={{ color: "var(--c-ink)" }}>{fn.title}</span>
                </div>
                <StatusTag tone={STATUS_TONE[fn.status] ?? "neutral"}>{statusLabel(fn.status)}</StatusTag>
              </div>
              {fn.description && <p className="mb-3 text-xs leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{fn.description}</p>}
              <div className="flex flex-col divide-y" style={{ borderColor: "var(--c-border)" }}>
                {fn.controls.map((c) => (
                  <div key={c.control_ref} className="flex items-start justify-between gap-4 py-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[11px]" style={{ color: "var(--c-ink-3)" }}>{c.control_ref}</span>
                        <span className="text-sm font-medium" style={{ color: "var(--c-ink)" }}>{c.title}</span>
                      </div>
                      {c.description && <p className="mt-1 text-xs leading-relaxed" style={{ color: "var(--c-ink-2)" }}>{c.description}</p>}
                    </div>
                    <StatusTag tone={STATUS_TONE[c.status] ?? "neutral"}>{statusLabel(c.status)}</StatusTag>
                  </div>
                ))}
              </div>
            </Panel>
          ))}
        </div>
      )}
    </div>
  );
}
