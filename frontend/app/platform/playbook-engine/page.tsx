import type { Metadata } from "next";
import { PlatformPage } from "@/components/platform-pages";

export const metadata: Metadata = {
  title: "Playbook Engine — Nirvet",
  description: "Versioned, auditable playbooks with approval gates and built-in reversal.",
};

export default function Page() {
  return <PlatformPage slug="playbook-engine" />;
}
