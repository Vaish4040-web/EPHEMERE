// EPHEMERE web config.
// The Umbral library ships as WebAssembly. Webpack must be told how to load .wasm files.
// (We use webpack on purpose: `next dev --webpack` / `next build --webpack`.)
/** @type {import('next').NextConfig} */
const nextConfig = {
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
