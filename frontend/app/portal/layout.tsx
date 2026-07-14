"use client";

// Customer portal shell (SRS §6.3 / UI-002). A distinct, role-scoped surface for customer users
// (customer_admin / customer_viewer) — separate from the provider SOC console. Guards on the session
// (getMe → /login) AND the audience: a provider/SOC role is redirected to /console, so the two portals
// never bleed into each other. Wired to the customer read-model (/customer/*), which is a positive-allowlist
// projection — customer users only ever see customer-safe fields by construction (readmodel package).

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { getMe, logout, type Me } from "@/lib/api";
import { Icon, NirvetMark } from "@/components/icons";

export function isCustomerRole(role?: string) {
  return !!role && role.startsWith("customer");
}

const NAV = [
  { label: "Overview", href: "/portal", icon: "grid" },
  { label: "Posture", href: "/portal/posture", icon: "activity" },
  { label: "Incidents", href: "/portal/incidents", icon: "alert-circle" },
  { label: "Alerts", href: "/portal/alerts", icon: "alert-triangle" },
  { label: "Assets", href: "/portal/assets", icon: "box" },
  { label: "Vulnerabilities", href: "/portal/vulnerabilities", icon: "shield" },
  { label: "Compliance", href: "/portal/compliance", icon: "file-text" },
];

export default function PortalLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [me, setMe] = useState<Me | null>(null);
  const [state, setState] = useState<"loading" | "ready">("loading");

  useEffect(() => {
    let alive = true;
    getMe()
      .then((u) => {
        if (!alive) return;
        if (!isCustomerRole(u.role)) {
          router.replace("/console");
          return;
        }
        setMe(u);
        setState("ready");
      })
      .catch(() => alive && router.replace("/login"));
    return () => {
      alive = false;
    };
  }, [router]);

  async function signOut() {
    try {
      await logout();
    } catch {
      /* clear regardless */
    }
    router.replace("/login");
  }

  if (state === "loading") {
    return <div className="flex min-h-screen items-center justify-center text-sm" style={{ color: "var(--c-ink-3)" }}>Verifying session…</div>;
  }

  return (
    <div className="flex h-screen flex-col overflow-hidden" style={{ background: "var(--c-bg)" }}>
      <header className="flex h-14 shrink-0 items-center gap-3 px-4" style={{ background: "var(--c-surface)", borderBottom: "1px solid var(--c-border)" }}>
        <Link href="/portal" className="flex items-center gap-2">
          <NirvetMark size={26} />
          <span className="text-sm font-extrabold tracking-tight">NIR<span style={{ color: "var(--c-primary)" }}>VET</span></span>
        </Link>
        <span className="ml-1 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide" style={{ background: "rgba(6,182,212,0.1)", color: "var(--c-accent)", border: "1px solid var(--c-border-strong)" }}>Customer portal</span>
        <nav className="ml-6 hidden items-center gap-1 md:flex">
          {NAV.map((n) => {
            const active = n.href === "/portal" ? pathname === n.href : pathname.startsWith(n.href);
            return (
              <Link key={n.href} href={n.href} className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm transition" style={active ? { background: "rgba(14,165,233,0.1)", color: "var(--c-ink)" } : { color: "var(--c-ink-2)" }}>
                <Icon name={n.icon} size={15} />{n.label}
              </Link>
            );
          })}
        </nav>
        <div className="ml-auto flex items-center gap-3">
          <span className="hidden text-xs sm:block" style={{ color: "var(--c-ink-3)" }}>{me?.email}</span>
          <button onClick={signOut} className="rounded-lg px-3 py-1.5 text-xs" style={{ border: "1px solid var(--c-border)", color: "var(--c-ink-2)" }}>Sign out</button>
        </div>
      </header>
      <main className="flex-1 overflow-y-auto p-8"><div className="mx-auto max-w-6xl">{children}</div></main>
    </div>
  );
}
