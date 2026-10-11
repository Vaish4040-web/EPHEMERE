// EPHEMERE web config.
// The Umbral library ships as WebAssembly. Webpack must be told how to load .wasm files.
// (We use webpack on purpose: `next dev --webpack` / `next build --webpack`.)
/** @type {import('next').NextConfig} */
const nextConfig = {
  // The browser only ever talks to this web app. Calls to /api/... are passed on to the gateway.
  async rewrites() {
    const gateway = process.env.GATEWAY_URL ?? "http://127.0.0.1:8000";
    return [{ source: "/api/:path*", destination: `${gateway}/api/:path*` }];
  },
  webpack: (config, { isServer }) => {
    config.experiments = { ...config.experiments, asyncWebAssembly: true };
    config.output.environment = { ...config.output.environment, asyncFunction: true };
    config.output.webassemblyModuleFilename = isServer
      ? "../static/wasm/[modulehash].wasm"
      : "static/wasm/[modulehash].wasm";
    return config;
  },
};

export default nextConfig;
