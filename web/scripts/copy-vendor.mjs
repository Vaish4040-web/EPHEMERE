// Copies the browser build of snarkjs into public/vendor so the page can load it as a plain <script>.
// (Loading snarkjs this way avoids bundler problems with its web workers.)
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "node_modules", "snarkjs", "build", "snarkjs.min.js");
const dst = join(root, "public", "vendor", "snarkjs.min.js");
if (!existsSync(src)) { console.error("snarkjs is not installed yet: run `npm install` first."); process.exit(1); }
mkdirSync(dirname(dst), { recursive: true });
copyFileSync(src, dst);
console.log("copied snarkjs.min.js to public/vendor");
