"use client";

// Knowledge base (CASE-010) — the tenant's runbook/reference library. Browse articles (GET /knowledge-base →
// {articles}) and author new ones (POST /knowledge-base). Articles are linkable to an incident from the case
// workspace (the KB-links panel on the incident detail). Provider tier; tenant-scoped, with global articles (no
// tenant_id) shown alongside. This surfaces a backend capability (custody.go CreateArticle/ListArticles) that had
// no UI — an analyst can now capture and find institutional knowledge instead of it living only in the API.

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiGet, apiPost, errorText } from "@/lib/api";
import { PageHeader, Panel, EmptyState, Button, StatusTag } from "@/components/ui";

type KBArticle = {
  id: string;
  tenant_id?: string | null;
  title: string;
  body?: string;
  url?: string;
  category?: string;
  tags: string[];
  created_at: string;
};

const inputStyle = { background: "var(--c-surface-2)", border: "1px solid var(--c-border)", color: "var(--c-ink)" } as const;

function fmt(dt?: string) {
  return dt ? new Date(dt).toLocaleDateString() : "—";
}

export default function KnowledgeBasePage() {
  const [articles, setArticles] = useState<KBArticle[]>([]);
  const [state, setState] = useState<"loading" | "ready">("loading");
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("");
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({ title: "", body: "", url: "", category: "", tags: "" });

  const load = useCallback(async () => {
    try {
      const r = await apiGet<{ articles: KBArticle[] | null }>("/knowledge-base");
      setArticles(r.articles ?? []);
    } finally {
      setState("ready");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const categories = useMemo(
    () => Array.from(new Set(articles.map((a) => a.category).filter(Boolean) as string[])).sort(),
    [articles],
  );

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return articles.filter((a) => {
      if (cat && a.category !== cat) return false;
      if (!needle) return true;
      return (
        a.title.toLowerCase().includes(needle) ||
        (a.body ?? "").toLowerCase().includes(needle) ||
        (a.tags ?? []).some((t) => t.toLowerCase().includes(needle))
      );
    });
  }, [articles, q, cat]);

  async function create() {
    setMsg(null);
    setBusy(true);
    try {
      const tags = form.tags.split(",").map((t) => t.trim()).filter(Boolean);
      await apiPost("/knowledge-base", {
        title: form.title.trim(),
        body: form.body.trim(),
        url: form.url.trim(),
        category: form.category.trim(),
        tags,
      });
      setMsg({ tone: "ok", text: "Article published." });
      setForm({ title: "", body: "", url: "", category: "", tags: "" });
      setShowNew(false);
      await load();
    } catch (e) {
      setMsg({ tone: "danger", text: errorText(e, "Publishing an article requires an analyst role.", "Could not publish the article.") });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Knowledge base"
        sub="Runbooks and reference articles — searchable, linkable to any case"
        actions={<Button size="sm" onClick={() => setShowNew((v) => !v)}>{showNew ? "Cancel" : "New article"}</Button>}
      />

      {msg && <p className="mb-3 text-[13px]" style={{ color: msg.tone === "ok" ? "var(--c-ok)" : "var(--c-danger)" }}>{msg.text}</p>}

      {showNew && (
        <Panel title="New article" sub="Capture a runbook, playbook note or reference">
          <div className="space-y-3">
            <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
              Title <span style={{ color: "var(--c-danger)" }}>*</span>
              <input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} />
            </label>
            <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
              Body
              <textarea value={form.body} onChange={(e) => setForm({ ...form, body: e.target.value })} rows={5} className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} />
            </label>
            <div className="grid grid-cols-2 gap-3">
              <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
                Category
                <input value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} placeholder="e.g. phishing, ransomware" className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} />
              </label>
              <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
                Reference URL
                <input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} placeholder="https://…" className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} />
              </label>
            </div>
            <label className="block text-[12px]" style={{ color: "var(--c-ink-3)" }}>
              Tags <span className="text-[10px]">(comma-separated)</span>
              <input value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} placeholder="mitre-t1566, email, credential-theft" className="mt-1 w-full rounded-lg px-3 py-2 text-sm" style={inputStyle} />
            </label>
            <Button disabled={busy || !form.title.trim()} onClick={create}>Publish article</Button>
          </div>
        </Panel>
      )}

      <div className="mb-4 mt-2 flex flex-wrap gap-2">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, body or tags…" className="flex-1 rounded-lg px-3 py-2 text-sm" style={inputStyle} />
        <select value={cat} onChange={(e) => setCat(e.target.value)} className="rounded-lg px-3 py-2 text-sm" style={inputStyle}>
          <option value="">All categories</option>
          {categories.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>

      {state === "loading" ? (
        <div className="p-6 text-sm" style={{ color: "var(--c-ink-3)" }}>Loading…</div>
      ) : filtered.length === 0 ? (
        <EmptyState title={articles.length === 0 ? "No articles yet" : "No matches"} hint={articles.length === 0 ? "Publish the first runbook to build your team's knowledge base." : "Try a different search or category."} />
      ) : (
        <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))" }}>
          {filtered.map((a) => (
            <div key={a.id} className="rounded-xl p-4" style={{ background: "var(--c-surface)", border: "1px solid var(--c-border)" }}>
              <div className="flex items-start justify-between gap-2">
                <h3 className="text-[14px] font-semibold" style={{ color: "var(--c-ink)" }}>{a.title}</h3>
                {!a.tenant_id && <StatusTag tone="info">global</StatusTag>}
              </div>
              {a.category && <div className="mt-1 text-[11px] uppercase tracking-wide" style={{ color: "var(--c-ink-3)" }}>{a.category}</div>}
              {a.body && <p className="mt-2 line-clamp-4 text-[13px]" style={{ color: "var(--c-ink-2)" }}>{a.body}</p>}
              {a.url && (
                <a href={a.url} target="_blank" rel="noopener noreferrer" className="mt-2 block truncate text-[12px]" style={{ color: "var(--c-primary)" }}>{a.url}</a>
              )}
              {a.tags.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1">
                  {a.tags.map((t) => <span key={t} className="rounded-full px-2 py-0.5 text-[10px]" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-3)", border: "1px solid var(--c-border)" }}>{t}</span>)}
                </div>
              )}
              <div className="mt-3 text-[10px]" style={{ color: "var(--c-ink-3)" }}>Added {fmt(a.created_at)}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
