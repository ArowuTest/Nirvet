"use client";

// AI response proposals surface (copilot completion incr1 — closes gate 2e's UI side). The analyst asks the AI to
// DRAFT a recommendation (POST /ai/incidents/{id}/draft-proposal); each pending proposal shows the AI's authored
// rationale + evidence citations + its ADVISORY risk (distinct from the enforced catalog risk). A senior promotes one
// into a run by picking an enacting playbook (POST /ai/proposals/{id}/accept {playbook_id}) — the SAME verified
// airesponse.Accept → soar gate; the AI never executes. Reject dismisses a draft (runs nothing).

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, ApiError } from "@/lib/api";
import { Panel, Table, Th, Td, StatusTag, EmptyState, Button } from "@/components/ui";

type Proposal = {
  id: string; recommended_action: string; connector_key?: string; rationale?: string;
  evidence_citations: string[] | null; risk_class: string; status: string;
};
type Playbook = { id: string; name: string; enabled?: boolean };

const selectStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

function riskTone(r: string): "danger" | "warn" | "neutral" {
  return r === "business_critical" || r === "high" ? "danger" : r === "medium" ? "warn" : "neutral";
}

export default function AiProposals({ incidentId, playbooks, onAccepted }: { incidentId: string; playbooks: Playbook[]; onAccepted?: () => void }) {
  const [proposals, setProposals] = useState<Proposal[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [drafting, setDrafting] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [pick, setPick] = useState<Record<string, string>>({});
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);

  const reload = useCallback(async () => {
    try {
      const res = await apiGet<{ proposals: Proposal[] | null }>(`/ai/proposals?incident_ref=${incidentId}`);
      setProposals(res.proposals ?? []);
    } catch { /* best-effort — the panel still renders its draft control */ }
    finally { setLoaded(true); }
  }, [incidentId]);

  useEffect(() => { reload(); }, [reload]);

  const draft = useCallback(async () => {
    setDrafting(true); setMsg(null);
    try {
      const res = await apiPost<{ declined?: boolean; reason?: string }>(`/ai/incidents/${incidentId}/draft-proposal`);
      if (res && res.declined) {
        setMsg({ tone: "danger", text: res.reason || "The AI declined to recommend a response." });
      } else {
        setMsg({ tone: "ok", text: "The AI drafted a recommendation. Review it below, then a senior can accept it into a run." });
      }
      await reload();
    } catch (e) {
      setMsg({ tone: "danger", text: e instanceof ApiError ? e.message : "Could not draft a recommendation." });
    } finally { setDrafting(false); }
  }, [incidentId, reload]);

  const accept = useCallback(async (id: string) => {
    const pb = pick[id];
    if (!pb) { setMsg({ tone: "danger", text: "Choose an enacting playbook first — it must contain the recommended action." }); return; }
    setBusy(id); setMsg(null);
    try {
      await apiPost(`/ai/proposals/${id}/accept`, { playbook_id: pb });
      setMsg({ tone: "ok", text: "Accepted — the response is promoted into a run through the authority gates." });
      await reload();
      onAccepted?.();
    } catch (e) {
      setMsg({ tone: "danger", text: e instanceof ApiError ? e.message : "Could not accept the proposal (a senior role is required, and the playbook must contain the action)." });
    } finally { setBusy(null); }
  }, [pick, reload, onAccepted]);

  const reject = useCallback(async (id: string) => {
    setBusy(id); setMsg(null);
    try { await apiPost(`/ai/proposals/${id}/reject`); await reload(); }
    catch (e) { setMsg({ tone: "danger", text: e instanceof ApiError ? e.message : "Could not reject the proposal." }); }
    finally { setBusy(null); }
  }, [reload]);

  const pending = proposals.filter((p) => p.status === "pending");
  const decided = proposals.filter((p) => p.status !== "pending");

  return (
    <Panel title="AI response proposals" sub="The AI drafts a catalog-bound recommendation; a senior accepts it into a run — the AI never executes">
      <div className="mb-3 flex items-center gap-3">
        <Button size="sm" disabled={drafting} onClick={draft}>{drafting ? "Drafting…" : "Draft with AI"}</Button>
        <span className="text-[11px]" style={{ color: "var(--c-ink-3)" }}>Uses the redacted incident context; declines when evidence is thin.</span>
      </div>

      {msg && (
        <div className="mb-3 rounded-lg px-3 py-2 text-sm" style={{ border: "1px solid var(--c-border)", background: msg.tone === "ok" ? "rgba(34,197,94,0.12)" : "rgba(239,68,68,0.12)", color: msg.tone === "ok" ? "#22c55e" : "#ef4444" }}>{msg.text}</div>
      )}

      {loaded && pending.length === 0 && decided.length === 0 && (
        <EmptyState title="No AI proposals yet" hint="Click “Draft with AI” to have the copilot author a response recommendation for this incident." />
      )}

      {pending.map((p) => (
        <div key={p.id} className="mb-3 rounded-xl p-3" style={{ border: "1px solid var(--c-border)", background: "var(--c-surface-2)" }}>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold" style={{ color: "var(--c-ink)" }}>{p.recommended_action}</span>
            <StatusTag tone={riskTone(p.risk_class)}>AI-assessed risk: {p.risk_class} (advisory)</StatusTag>
            <StatusTag tone="warn">pending</StatusTag>
          </div>
          {p.rationale && <p className="mt-2 text-sm" style={{ color: "var(--c-ink-2)" }}>{p.rationale}</p>}
          {(p.evidence_citations ?? []).length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {(p.evidence_citations ?? []).map((c) => (
                <span key={c} className="rounded px-1.5 py-0.5 font-mono text-[10px]" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)", color: "var(--c-ink-3)" }}>{c}</span>
              ))}
            </div>
          )}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <select value={pick[p.id] ?? ""} onChange={(e) => setPick((m) => ({ ...m, [p.id]: e.target.value }))} className="rounded-lg px-2.5 py-1.5 text-xs" style={selectStyle}>
              <option value="">{playbooks.length === 0 ? "No enabled playbooks" : "Enacting playbook…"}</option>
              {playbooks.map((pb) => <option key={pb.id} value={pb.id}>{pb.name}</option>)}
            </select>
            <Button size="sm" disabled={busy === p.id || playbooks.length === 0} onClick={() => accept(p.id)}>{busy === p.id ? "…" : "Accept → run"}</Button>
            <Button size="sm" variant="ghost" disabled={busy === p.id} onClick={() => reject(p.id)}>Reject</Button>
          </div>
          <p className="mt-2 text-[10px]" style={{ color: "var(--c-ink-3)" }}>The enforced authority gate uses the catalog risk for this action, not the AI’s advisory assessment. A senior who did not draft it must accept.</p>
        </div>
      ))}

      {decided.length > 0 && (
        <Table head={<><Th>Action</Th><Th>AI risk (advisory)</Th><Th className="text-right">Outcome</Th></>}>
          {decided.map((p) => (
            <tr key={p.id}>
              <Td className="text-xs font-medium">{p.recommended_action}</Td>
              <Td className="text-xs">{p.risk_class}</Td>
              <Td className="text-right"><StatusTag tone={p.status === "accepted" ? "ok" : "neutral"}>{p.status}</StatusTag></Td>
            </tr>
          ))}
        </Table>
      )}
    </Panel>
  );
}
