import type { Metadata } from "next";
import { PlatformPage } from "@/components/platform-pages";

export const metadata: Metadata = {
  title: "AI Co-pilot — Nirvet",
  description: "An analyst co-pilot with governed egress and a human always in the loop.",
};

export default function Page() {
  return <PlatformPage slug="ai-copilot" />;
}
