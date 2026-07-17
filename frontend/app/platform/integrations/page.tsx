import type { Metadata } from "next";
import { PlatformPage } from "@/components/platform-pages";

export const metadata: Metadata = {
  title: "Integrations — Nirvet",
  description: "Connect EDR, SIEM, cloud, identity, and email through a governed connector layer.",
};

export default function Page() {
  return <PlatformPage slug="integrations" />;
}
