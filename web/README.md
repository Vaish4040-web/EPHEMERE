# EPHEMERE web app (Member D)

Right now this app has one useful page: **`/lab`, the browser self-test.** It runs every building block inside the browser and shows PASS, FAIL or SKIP for each check. The real vault and company portals will be built here later.

## Run it
You need Node.js 20 or newer. In the terminal, inside the `web` folder:

```
npm install
npm run dev
```

Then open **http://localhost:3000/lab** and click **Run all checks**. You should see **19 passed, 0 failed, 0 skipped**.

- The first `npm install` takes a few minutes (Next.js is big).
- The proof files (`web/public/zk/`) are already in the zip, so the zero-knowledge checks work straight away. If that folder is empty, those checks show SKIP and tell you what to do. To rebuild the files yourself: in `circuits/` run `./build.sh` (Git Bash), then `npm run zk:prepare`.
- Try **Chrome or Edge** first.

## What the 19 checks cover
| Group | Checks |
|---|---|
| This browser | secure page, WebCrypto + WebAssembly + Web Workers available |
| File encryption | encrypt/decrypt, new IV each time, 1 changed bit rejected, wrong asset ID rejected |
| Sharing (Umbral) | library loads, owner opens own key, full share flow, other party rejected, unsigned cfrags rejected, 2-of-3 |
| Zero-knowledge proof | adult proof created and verified in the browser, verifier's values are in the proof, no date of birth in public values, 15-year-old cannot prove, replayed proof rejected |

## Test it together with the Python server side (optional)
At the bottom of the page you can make a "share bundle" and let the Python code open it. Steps are in `spikes/pre/README.md`. In my test, a bundle created in a real browser was opened correctly by the Python proxy and access service.

## Results from my test (headless Chrome 153 on Linux, one CPU thread)
- 19 of 19 checks passed, both with `npm run dev` and with a production build.
- Zero-knowledge proof: about 2.3 seconds to create, 27 ms to verify. A normal laptop with more CPU threads should be faster. **Measure on your own laptops and write the numbers in the report.**
- Sharing steps (make pieces, re-encrypt, verify and decrypt): a few milliseconds each.

## Things to know
- **Why `--webpack`?** The Umbral library is WebAssembly, and Next.js 16 uses a different build tool (Turbopack) by default that I did not test. The scripts in `package.json` already add `--webpack`, so just use `npm run dev` and `npm run build`.
- **Why is snarkjs copied?** `npm run dev` first copies a ready-made browser file (`snarkjs.min.js`) into `public/vendor/`. Loading it as a plain script avoids problems with bundlers and web workers.
- **`npm install` may warn about "3 high severity vulnerabilities".** They come from tools inside snarkjs's command line (`snarkjs` is only used to copy that one browser file). The web page does not use them, and `npm audit --omit=dev` shows 0. **Do not run `npm audit fix --force`.**
- **Never commit** `public/zk/`, `public/vendor/`, `node_modules/` or `bob_secret.json`. They are already in `.gitignore`.
- The proof files here come from a **development-only** trusted setup and a **simulated** issuer. Say so in the report.

## Not tested yet
Firefox, Safari, a real Windows machine, and slow computers. IPFS from the page (the plan is that the browser sends the encrypted file to the backend, which talks to IPFS).

## Files
| File | Role |
|---|---|
| `app/lab/page.js` | The self-test page |
| `lib/lab.js` | The list of checks |
| `lib/aes.js` | AES-GCM-256 with WebCrypto |
| `lib/pre.js` | Umbral sharing helpers (owner, proxy, delegate) |
| `lib/zk.js` | Zero-knowledge proof helpers (user and verifier roles) |
| `lib/bytes.js` | base64 and hashing helpers |
| `scripts/copy-vendor.mjs` | Copies the snarkjs browser file |
| `next.config.mjs` | Tells webpack how to load WebAssembly |
