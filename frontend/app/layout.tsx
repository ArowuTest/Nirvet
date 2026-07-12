import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

// Inter is the type family used throughout the Nirvet mockups. Loaded via next/font
// (self-hosted at build — no runtime CDN request, and no CSP/privacy concern).
const inter = Inter({ subsets: ["latin"], display: "swap", variable: "--font-inter" });

export const metadata: Metadata = {
  title: "Nirvet — SOC Platform",
  description: "Network Intelligence, Risk Visibility & Event Triage",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={inter.variable}>
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
