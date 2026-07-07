import Link from "next/link";

export default function Home() {
  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col items-center justify-center gap-8 px-6 text-center">
      <div>
        <h1 className="text-5xl font-bold tracking-tight text-white">Nirvet</h1>
        <p className="mt-3 text-lg text-blue-300">
          Network Intelligence · Risk Visibility · Event Triage
        </p>
        <p className="mt-4 max-w-xl text-slate-400">
          A modular Security Operations Platform — SOCaaS, MDR, Managed XDR, Sovereign SOC and
          MSSP white-label. Native SOC operating layer, integration-first.
        </p>
      </div>
      <div className="flex gap-4">
        <Link
          href="/login"
          className="rounded-lg bg-blue-600 px-6 py-3 font-medium text-white transition hover:bg-blue-500"
        >
          Sign in to the SOC console
        </Link>
      </div>
      <p className="text-xs text-slate-600">Scaffold build — planning stage. Not production.</p>
    </main>
  );
}
