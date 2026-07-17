import type { Metadata } from "next";
import { PlatformPage } from "@/components/platform-pages";

export const metadata: Metadata = {
  title: "Evidence Management — Nirvet",
  description: "Timestamped, hashed, chain-of-custody evidence ready for audit and legal review.",
};

export default function Page() {
  return <PlatformPage slug="evidence-management" />;
}
