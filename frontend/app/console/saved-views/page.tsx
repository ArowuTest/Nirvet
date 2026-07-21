"use client";

// Saved hunt views (#172) — reusable, named hunt filters. List / run / delete the tenant's saved views
// (GET/POST/DELETE /investigation/saved-views, POST .../{id}/run). Running a view executes its hunt through the
// same security envelope and returns matching events. Read + own-view management, tenant-scoped, provider+.

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, apiPost, apiDelete, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, SevBadge, StatusTag, EmptyState, Button } from "@/components/ui";

type SavedView = {
  id: string; name: string; description?: string;
  lookback_seconds: number; limit?: number; created_at: string; updated_at: string;
};
type EventRow = {
  id: string; event_time: string; source: string; class: string; activity: string;
  severity: string; confidence: number; actor_ref: string; target_ref: string;
};
type HuntResult = { rows: EventRow[] | null; count: number };

function lookbackLabel(secs: number) {
  if (!secs) return "—";
  const h = Math.round(secs / 3600);
  if (h < 24) return `${h}h`;
  return `${Math.round(h / 24)}d`;
}

export default function SavedViewsPage() {
  const [views, setViews] = useState<SavedView[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [err, setErr] = useState("");
  const [runId, setRunId] = useState<string | null>(null);
  const [result, setResult] = useState<HuntResult | null>(null);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try { setViews(await apiGet<SavedView[]>("/investigation/saved-views") ?? []); setState("ready"); }
    catch (e) { setErr(e instanceof ApiError ? e.message : "Could not load saved views."); setState("error"); }
  }, []);

  useEffect(() => { reload(); }, [reload]);

  const run = useCallback(async (id: string) => {
    setRunningId(id); setRunId(id); setResult(null); setErr("");
    try { setResult(await apiPost<HuntResult>(`/investigation/saved-views/${id}/run`)); }
    catch (e) { setErr(e instanceof ApiError ? e.message : "Could not run the view."); }
    finally { setRunningId(null); }
  }, []);

  const remove = useCallback(async (id: string) => {
    setBusy(id);
    try { await apiDelete(`/investigation/saved-views/${id}`); if (runId === id) { setRunId(null); setResult(null); } await reload(); }
    catch (e) { setErr(e instanceof ApiError ? e.message : "Could not delete the view."); }
    finally { setBusy(null); }
  }, [reload, runId]);

  const rows = result?.rows ?? [];

  return (
    <div>
      <PageHeader title="Saved views" sub="Reusable hunt filters — run one to execute its query through the security envelope" />

      {state === "loading" && <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>}
      {state === "error" && <div className="rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(239,68,68,0.12)", color: "#ef4444", border: "1px solid var(--c-border)" }}>{err}</div>}

      {state === "ready" && (
        <div className="space-y-5">
          <Panel title="Views" sub="Saved from the Threat Hunt query builder" bodyStyle={{ padding: 0 }}>
            {views.length === 0 ? (
              <div className="p-6 text-center">
                <EmptyState title="No saved views yet" hint="Build a query in Threat Hunt and save it to reuse here." />
                <Link href="/console/hunt" className="mt-3 inline-block text-xs font-medium" style={{ color: "var(--c-primary)" }}>Go to Threat Hunt →</Link>
              </div>
            ) : (
              <Table head={<><Th>Name</Th><Th>Lookback</Th><Th>Limit</Th><Th>Updated</Th><Th className="text-right">Actions</Th></>}>
                {views.map((v) => (
                  <tr key={v.id} className="transition hover:bg-[color:var(--c-surface-2)]">
                    <Td>
                      <div className="font-medium" style={{ color: "var(--c-ink)" }}>{v.name}</div>
                      {v.description && <div className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>{v.description}</div>}
                    </Td>
                    <Td className="text-xs">{lookbackLabel(v.lookback_seconds)}</Td>
                    <Td className="text-xs">{v.limit || "—"}</Td>
                    <Td className="text-xs">{v.updated_at ? new Date(v.updated_at).toLocaleDateString() : "—"}</Td>
                    <Td className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button size="sm" disabled={runningId === v.id} onClick={() => run(v.id)}>{runningId === v.id ? "Running…" : "Run"}</Button>
                        <Button size="sm" variant="ghost" disabled={busy === v.id} onClick={() => remove(v.id)}>{busy === v.id ? "…" : "Delete"}</Button>
                      </div>
                    </Td>
                  </tr>
                ))}
              </Table>
            )}
          </Panel>

          {runId && (
            <Panel title="Results" sub={result ? `${result.count} event${result.count === 1 ? "" : "s"} matched` : "Running…"} bodyStyle={{ padding: 0 }}>
              {!result ? <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Running…</div> : rows.length === 0 ? (
                <div className="p-6"><EmptyState title="No matches" hint="This view's query returned no events in its window." /></div>
              ) : (
                <Table head={<><Th>When</Th><Th>Source</Th><Th>Class</Th><Th>Activity</Th><Th>Severity</Th><Th className="text-right">Actor → Target</Th></>}>
                  {rows.map((r) => (
                    <tr key={r.id} className="transition hover:bg-[color:var(--c-surface-2)]">
                      <Td className="whitespace-nowrap text-xs">{r.event_time ? new Date(r.event_time).toLocaleString() : "—"}</Td>
                      <Td className="text-xs">{r.source || "—"}</Td>
                      <Td className="text-xs">{r.class || "—"}</Td>
                      <Td className="text-xs">{r.activity || "—"}</Td>
                      <Td>{r.severity ? <SevBadge severity={r.severity} /> : "—"}</Td>
                      <Td className="text-right font-mono text-[11px]">{r.actor_ref || "—"} → {r.target_ref || "—"}</Td>
                    </tr>
                  ))}
                </Table>
              )}
            </Panel>
          )}

          <div className="text-xs"><StatusTag tone="neutral">runs through the hunt security envelope</StatusTag></div>
        </div>
      )}
    </div>
  );
}
