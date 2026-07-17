import type { Metadata } from "next";
import { PlatformPage } from "@/components/platform-pages";

export const metadata: Metadata = {
  title: "Detection & Response — Nirvet",
  description: "Correlate signals across your data estate and act with governed, reversible response actions.",
};

export default function Page() {
  return <PlatformPage slug="detection-response" />;
}
