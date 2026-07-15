/** @type {import('next').NextConfig} */

// Derive the exact API origin so CSP connect-src allows the cross-site API (Render) without opening connect-src to
// the world. NEXT_PUBLIC_API_BASE is a build-time value (e.g. https://nirvet-api.onrender.com); reduce it to
// scheme+host. Falls back to same-origin only if unset.
function apiOrigin() {
  const raw = process.env.NEXT_PUBLIC_API_BASE || "";
  try {
    return raw ? new URL(raw).origin : "";
  } catch {
    return "";
  }
}

// Content-Security-Policy for the SPA. Allowances are kept as tight as the app permits:
//  - script-src 'unsafe-inline': Next.js injects an inline bootstrap/hydration script; without a nonce middleware
//    this is required. A nonce-based CSP is the stricter follow-up (tracked separately).
//  - style-src 'unsafe-inline': the console renders extensively via inline style={{…}} + design-token vars.
//  - img-src https: data:: white-label branding logos are operator-supplied https URLs; data: covers the favicon.
//  - connect-src includes the API origin (XHR/fetch to the cross-site backend) plus 'self'.
//  - frame-ancestors 'none' (+ X-Frame-Options DENY): clickjacking defense. object-src 'none', base-uri 'self',
//    form-action 'self': lock down injection/exfil vectors.
function contentSecurityPolicy() {
  const connect = ["'self'", apiOrigin()].filter(Boolean).join(" ");
  return [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self' data:",
    `connect-src ${connect}`,
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "upgrade-insecure-requests",
  ].join("; ");
}

const securityHeaders = [
  { key: "Content-Security-Policy", value: contentSecurityPolicy() },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" },
  // HSTS is already set at the edge; not duplicated here.
];

const nextConfig = {
  reactStrictMode: true,
  // Standalone output produces a minimal self-contained server for the Docker
  // image (used for GCP/Cloud Run/local). Vercel ignores this and deploys natively.
  output: "standalone",
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
