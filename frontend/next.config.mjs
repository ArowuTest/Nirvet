/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Standalone output produces a minimal self-contained server for the Docker
  // image (used for GCP/Cloud Run/local). Vercel ignores this and deploys natively.
  output: "standalone",
};

export default nextConfig;
