import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Nirvet — SOC Platform",
  description: "Network Intelligence, Risk Visibility & Event Triage",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
