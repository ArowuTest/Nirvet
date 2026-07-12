"use client";

// Console shell + client-side route guard. Under ADR-0007 the session lives in HttpOnly cookies JS can't read,
// so we can't gate on a token in localStorage — instead we probe GET /me (which the browser answers with the
// access cookie, transparently refreshing it if expired via lib/api's single-flight refresh). 200 → render;
// 401 → the session is truly gone → redirect to /login. This is defence-in-depth UX only; the BACKEND RLS +
// auth middleware are the real access control on every API call.

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { getMe, logout, logoutAll, type Me } from "@/lib/api";

const nav = [
  { href: "/console", label: "Dashboard" },
  { href: "/console/alerts", label: "Alerts" },
  { href: "/console/incidents", label: "Incidents" },
  { href: "/console/events", label: "Events" },
];

export default function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [me, setMe] = useState<Me | null>(null);
  const [state, setState] = useState<"loading" | "ready">("loading");

  useEffect(() => {
    let alive = true;
    getMe()
      .then((u) => {
        if (!alive) return;
        setMe(u);
        setState("ready");
      })
      .catch(() => {
        if (alive) router.replace("/login");
      });
    return () => {
      alive = false;
    };
  }, [router]);

  async function signOut(everywhere: boolean) {
    try {
      await (everywhere ? logoutAll() : logout());
    } catch {
      /* best-effort; clear the UI regardless */
    }
    router.replace("/login");
  }

  if (state === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm" style={{ color: "var(--c-ink-3)" }}>
        Verifying session…
      </div>
    );
  }

  return (
    <div className="flex min-h-screen">
      <aside
        className="flex w-60 shrink-0 flex-col p-4"
        style={{ background: "var(--c-surface)", borderRight: "1px solid var(--c-border)" }}
      >
        <div className="mb-6 flex items-center gap-2.5">
          <svg width="28" height="28" viewBox="0 0 36 36" fill="none" aria-hidden="true">
            <path d="M18 3L33 8.5V18C33 26.5 18 33 18 33C18 33 3 26.5 3 18V8.5L18 3Z" fill="rgba(14,165,233,0.12)" stroke="#0EA5E9" strokeWidth="1.5" strokeLinejoin="round" />
            <path d="M12 12L12 24L24 12L24 24" stroke="#0EA5E9" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
            <circle cx="24" cy="24" r="2.5" fill="#06B6D4" />
          </svg>
          <div>
            <div className="text-sm font-extrabold leading-none tracking-tight">
              NIR<span style={{ color: "var(--c-primary)" }}>VET</span>
            </div>
            <div className="mt-1 text-[11px]" style={{ color: "var(--c-ink-3)" }}>
              SOC Console
            </div>
          </div>
        </div>

        <nav className="space-y-1">
          {nav.map((n) => {
            const active = pathname === n.href;
            return (
              <Link
                key={n.href}
                href={n.href}
                className="block rounded-lg px-3 py-2 text-sm transition"
                style={
                  active
                    ? { background: "rgba(14,165,233,0.1)", color: "var(--c-ink)" }
                    : { color: "var(--c-ink-2)" }
                }
              >
                {n.label}
              </Link>
            );
          })}
        </nav>

        <div className="mt-auto space-y-3 pt-8">
          {me && (
            <div className="rounded-lg px-3 py-2 text-xs" style={{ background: "var(--c-surface-2)", color: "var(--c-ink-3)" }}>
              <div className="truncate" style={{ color: "var(--c-ink-2)" }} title={me.email}>
                {me.email}
              </div>
              <div className="mt-0.5 uppercase tracking-wide">{me.role.replace(/_/g, " ")}</div>
            </div>
          )}
          <button
            onClick={() => signOut(false)}
            className="w-full rounded-lg px-3 py-2 text-sm transition"
            style={{ border: "1px solid var(--c-border)", color: "var(--c-ink-2)" }}
          >
            Sign out
          </button>
          <button
            onClick={() => signOut(true)}
            className="w-full rounded-lg px-3 py-2 text-xs transition"
            style={{ color: "var(--c-ink-3)" }}
            title="Ends every active session on all your devices"
          >
            Sign out everywhere
          </button>
        </div>
      </aside>
      <main className="flex-1 p-8">{children}</main>
    </div>
  );
}
