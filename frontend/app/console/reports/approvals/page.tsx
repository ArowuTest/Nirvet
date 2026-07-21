"use client";

// Report approval queue (#173) — the four-eyes gate on report release, made visible. A review-required report sits
// in pending_review until a SENIOR actor who is NOT its creator approves (releasing the download) or rejects it with
// a reason. Manager-gated (GET /reports/pending-approval, POST /reports/{id}/approve|reject) — matches the route
// guard. Without this UI the queue was backend-only and reports could never actually clear review.

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, apiPost, API_BASE, ApiError } from "@/lib/api";
import { PageHeader, Panel, Table, Th, Td, StatusTag, EmptyState, Button } from "@/components/ui";

type Report = {
  id: string; type: string; format: string; status: string; review_status: string;
  row_count: number; byte_size: number; created_by: string; created_at: string;
};

const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

function bytes(n: number): string {
  if (!n) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export default function ReportApprovalsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [rejecting, setRejecting] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [flash, setFlash] = useState("");

  const reload = useCallback(async () => {
    try {
      const res = await apiGet<{ reports: Report[] | null }>("/reports/pending-approval");
      setReports(res.reports ?? []); setState("ready");
    } catch (e) { setErr(e instanceof ApiError ? e.message : "Could not load the approval queue."); setState("error"); }
  }, []);

  useEffect(() => { reload(); }, [reload]);

  const approve = useCallback(async (id: string) => {
    setBusy(id); setErr("");
    try { await apiPost(`/reports/${id}/approve`); setFlash("Report approved — the download is now released."); await reload(); }
    catch (e) { setErr(e instanceof ApiError ? e.message : "Could not approve the report."); }
    finally { setBusy(null); }
  }, [reload]);

  const reject = useCallback(async (id: string) => {
    if (!reason.trim()) return;
    setBusy(id); setErr("");
    try { await apiPost(`/reports/${id}/reject`, { reason: reason.trim() }); setFlash("Report rejected."); setRejecting(null); setReason(""); await reload(); }
    catch (e) { setErr(e instanceof ApiError ? e.message : "Could not reject the report."); }
    finally { setBusy(null); }
  }, [reason, reload]);

  return (
    <div>
      <PageHeader title="Report approvals" sub="Four-eyes review — a senior who did not create the report approves its release or rejects it" />

      <div className="mb-4 text-xs"><Link href="/console/reports" style={{ color: "var(--c-primary)" }}>← Back to Reports</Link></div>

      {flash && <div className="mb-4 rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(34,197,94,0.12)", color: "#22c55e", border: "1px solid var(--c-border)" }}>{flash}</div>}
      {err && <div className="mb-4 rounded-lg px-4 py-2.5 text-sm" style={{ background: "rgba(239,68,68,0.12)", color: "#ef4444", border: "1px solid var(--c-border)" }}>{err}</div>}

      {state === "loading" && <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>}

      {state === "ready" && (
        <Panel title="Awaiting review" sub={`${reports.length} report${reports.length === 1 ? "" : "s"} pending sign-off`} bodyStyle={{ padding: 0 }}>
          {reports.length === 0 ? (
            <div className="p-6"><EmptyState title="Nothing awaiting review" hint="No report is currently pending approval. Reports that require review appear here for a senior to release or reject." /></div>
          ) : (
            <Table head={<><Th>Report</Th><Th>Format</Th><Th>Rows</Th><Th>Size</Th><Th>Requested</Th><Th className="text-right">Decision</Th></>}>
              {reports.map((r) => (
                <tr key={r.id} className="align-top transition hover:bg-[color:var(--c-surface-2)]">
                  <Td>
                    <div className="font-medium" style={{ color: "var(--c-ink)" }}>{r.type}</div>
                    <StatusTag tone="warn">{r.review_status || "pending_review"}</StatusTag>
                  </Td>
                  <Td className="text-xs uppercase">{r.format}</Td>
                  <Td className="text-xs">{r.row_count}</Td>
                  <Td className="text-xs">{bytes(r.byte_size)}</Td>
                  <Td className="text-xs">{r.created_at ? new Date(r.created_at).toLocaleString() : "—"}</Td>
                  <Td className="text-right">
                    {rejecting === r.id ? (
                      <div className="flex flex-col items-end gap-2">
                        <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason for rejection (required)" className="w-56 rounded-lg px-2.5 py-1.5 text-xs" style={inputStyle} />
                        <div className="flex gap-2">
                          <Button size="sm" variant="danger" disabled={busy === r.id || !reason.trim()} onClick={() => reject(r.id)}>{busy === r.id ? "…" : "Confirm reject"}</Button>
                          <Button size="sm" variant="ghost" onClick={() => { setRejecting(null); setReason(""); }}>Cancel</Button>
                        </div>
                      </div>
                    ) : (
                      <div className="flex justify-end gap-2">
                        <Button size="sm" disabled={busy === r.id} onClick={() => approve(r.id)}>{busy === r.id ? "…" : "Approve"}</Button>
                        <Button size="sm" variant="ghost" onClick={() => { setRejecting(r.id); setReason(""); }}>Reject</Button>
                      </div>
                    )}
                  </Td>
                </tr>
              ))}
            </Table>
          )}
        </Panel>
      )}

      <div className="mt-4 text-xs" style={{ color: "var(--c-ink-3)" }}>
        Approving releases the report&rsquo;s download (<span className="font-mono">{API_BASE}/reports/&lt;id&gt;/download</span>); the creator can never approve their own report.
      </div>
    </div>
  );
}
