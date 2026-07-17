"use client";

// Public site nav with a real mobile menu. Below md the section links collapse behind a hamburger that opens a
// full-width dropdown (links + Sign In + Request Demo); at md+ it's the standard inline bar. One component, used by
// the landing page and every marketing/legal page, so the mobile menu exists everywhere.

import Link from "next/link";
import { useState } from "react";
import { NirvetMark } from "@/components/icons";

const NAV_LINKS = [
  { label: "Platform", href: "/#why" },
  { label: "Deployment", href: "/#deployment" },
  { label: "By Industry", href: "/#industry" },
  { label: "Security", href: "/#security" },
];

export function SiteNav() {
  const [open, setOpen] = useState(false);
  return (
    <nav className="fixed inset-x-0 top-0 z-50 border-b backdrop-blur" style={{ background: "rgba(5,13,26,0.9)", borderColor: "var(--c-border)" }}>
      <div className="mx-auto flex h-16 max-w-7xl items-center gap-10 px-6 md:px-10">
        <Link href="/" className="flex items-center gap-2.5" onClick={() => setOpen(false)}>
          <NirvetMark size={32} />
          <span className="text-lg font-extrabold tracking-tight">NIR<span style={{ color: "var(--c-primary)" }}>VET</span></span>
        </Link>

        {/* Desktop links */}
        <div className="hidden flex-1 items-center gap-7 md:flex">
          {NAV_LINKS.map((l) => (
            <Link key={l.href} href={l.href} className="text-sm font-medium transition hover:text-white" style={{ color: "var(--c-ink-2)" }}>{l.label}</Link>
          ))}
        </div>
        <div className="ml-auto hidden items-center gap-3 md:flex">
          <Link href="/login" className="rounded-lg px-4 py-2 text-sm font-semibold transition" style={{ color: "var(--c-ink-2)", border: "1px solid var(--c-border)" }}>Sign In</Link>
          <Link href="/contact" className="rounded-lg px-5 py-2 text-sm font-semibold text-white transition" style={{ background: "var(--c-primary)" }}>Request Demo</Link>
        </div>

        {/* Mobile hamburger */}
        <button
          type="button"
          aria-label={open ? "Close menu" : "Open menu"}
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
          className="ml-auto flex h-10 w-10 items-center justify-center rounded-lg md:hidden"
          style={{ border: "1px solid var(--c-border)", color: "var(--c-ink)" }}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            {open ? <><line x1="6" y1="6" x2="18" y2="18" /><line x1="18" y1="6" x2="6" y2="18" /></> : <><line x1="3" y1="6" x2="21" y2="6" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="3" y1="18" x2="21" y2="18" /></>}
          </svg>
        </button>
      </div>

      {/* Mobile dropdown panel */}
      {open && (
        <div className="border-t md:hidden" style={{ borderColor: "var(--c-border)", background: "rgba(5,13,26,0.98)" }}>
          <div className="mx-auto flex max-w-7xl flex-col gap-1 px-6 py-4">
            {NAV_LINKS.map((l) => (
              <Link key={l.href} href={l.href} onClick={() => setOpen(false)} className="rounded-lg px-3 py-3 text-[15px] font-medium transition" style={{ color: "var(--c-ink)" }}>
                {l.label}
              </Link>
            ))}
            <div className="my-2 h-px" style={{ background: "var(--c-border)" }} />
            <Link href="/login" onClick={() => setOpen(false)} className="rounded-lg px-3 py-3 text-center text-[15px] font-semibold" style={{ color: "var(--c-ink)", border: "1px solid var(--c-border)" }}>
              Sign In
            </Link>
            <Link href="/contact" onClick={() => setOpen(false)} className="rounded-lg px-3 py-3 text-center text-[15px] font-semibold text-white" style={{ background: "var(--c-primary)" }}>
              Request Demo
            </Link>
          </div>
        </div>
      )}
    </nav>
  );
}
