// EPHEMERE IPFS spike tests.   Run:  npm test
// This script starts its OWN temporary IPFS node (Kubo, offline mode, random free port),
// runs the checks, and shuts it down. Nothing is left running.
import { createRequire } from "node:module";
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { IpfsClient, computeCid, decryptFile, encryptFile, fetchVerified } from "./vault.mjs";

const require = createRequire(import.meta.url);
const kubo = require("kubo");

let failures = 0;
const check = (name, ok, note = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${note ? `   (${note})` : ""}`);
  if (!ok) failures++;
};
const rejects = async (fn, test = () => true) => { try { await fn(); } catch (e) { return test(e); } return false; };
const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const randomBytes = (n) => { const out = new Uint8Array(n); for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536))); return out; };
const enc = new TextEncoder();

// --------------------------------------------------------------- start a node
const freePort = () => new Promise((res) => { const s = createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const repo = mkdtempSync(join(tmpdir(), "ephemere-ipfs-"));
const env = { ...process.env, IPFS_PATH: repo };
const bin = kubo.path();
const port = await freePort();
execFileSync(bin, ["init", "--profile=test"], { env, stdio: "ignore" });
execFileSync(bin, ["config", "Addresses.API", `/ip4/127.0.0.1/tcp/${port}`], { env, stdio: "ignore" });
execFileSync(bin, ["config", "Addresses.Gateway", "/ip4/127.0.0.1/tcp/0"], { env, stdio: "ignore" });
const daemon = spawn(bin, ["daemon", "--offline"], { env, stdio: "ignore" });
const ipfs = new IpfsClient(`http://127.0.0.1:${port}`);

let version = null;
for (let i = 0; i < 60 && !version; i++) {
  try { version = await ipfs.version(); } catch { await new Promise((r) => setTimeout(r, 500)); }
}
if (!version) { daemon.kill(); console.error("could not start the IPFS node"); process.exit(2); }
console.log(`INFO  using Kubo ${version} (offline, port ${port})`);

// find a byte string anywhere in the node's stored blocks
const repoContains = (needle) => {
  const n = Buffer.from(needle);
  const walk = (dir) => readdirSync(dir).some((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : readFileSync(p).includes(n);
  });
  return walk(join(repo, "blocks"));
};

try {
  const ASSET = "11111111-1111-4111-8111-111111111111";
  const MARKER = "PATIENT-RECORD-MARKER-7f3a9c";
  const secret = enc.encode(`${MARKER} blood group O+, no allergies. `.repeat(200));

  // ---- 1. full round trip ----
  const e1 = await encryptFile(secret, ASSET);
  const cid1 = await ipfs.add(e1.ciphertext);
  const back = await fetchVerified(ipfs, cid1);
  const plain = await decryptFile({ dek: e1.dek, iv: e1.iv, ciphertext: back, assetId: ASSET });
  check("round trip: encrypt -> IPFS -> fetch by CID -> verify -> decrypt gives the original file", sameBytes(plain, secret), cid1.slice(0, 20) + "...");

  // ---- 2. the node only ever sees ciphertext ----
  check("the IPFS node's stored blocks do NOT contain the plaintext", !repoContains(MARKER));
  await ipfs.add(enc.encode(`${MARKER}-CONTROL unencrypted control file`));
  check("control: an UNENCRYPTED file IS found in the blocks (so the search above really works)", repoContains(`${MARKER}-CONTROL`));

  // ---- 3. same file, encrypted twice ----
  const e2 = await encryptFile(secret, ASSET);
  const cid2 = await ipfs.add(e2.ciphertext);
  check("encrypting the same file twice gives a different IV and a different CID",
        !sameBytes(e1.iv, e2.iv) && cid1 !== cid2, "no 'same file' fingerprint leaks");

  // ---- 4. our CID calculation agrees with the real node for many sizes ----
  const sizes = [1, 1000, 262144, 262145, 1048576, 5000000];
  let allMatch = true;
  const detail = [];
  for (const n of sizes) {
    const data = randomBytes(n);
    const nodeCid = await ipfs.add(data);
    const ours = await computeCid(data);
    if (nodeCid !== ours) allMatch = false;
    detail.push(`${n}:${nodeCid === ours ? "ok" : "DIFF"}`);
  }
  check("our own CID calculation equals Kubo's for every size tested (including multi-chunk files)", allMatch, detail.join(" "));

  // ---- 5. a faulty or malicious node is caught by the CID check ----
  const lyingNode = {
    cat: async (cid) => { const b = await ipfs.cat(cid); const c = b.slice(); c[10] ^= 1; return c; },
  };
  check("a node that returns changed bytes is rejected (CID_MISMATCH)",
        await rejects(() => fetchVerified(lyingNode, cid1), (e) => /CID_MISMATCH/.test(e.message)));

  // ---- 6. encryption-level attacks ----
  const bad = e1.ciphertext.slice(); bad[5] ^= 1;
  check("AES-GCM rejects a ciphertext that was changed by even 1 bit",
        await rejects(() => decryptFile({ dek: e1.dek, iv: e1.iv, ciphertext: bad, assetId: ASSET }), (e) => e.name === "OperationError"));
  check("the wrong key cannot decrypt",
        await rejects(() => decryptFile({ dek: e2.dek, iv: e1.iv, ciphertext: e1.ciphertext, assetId: ASSET }), (e) => e.name === "OperationError"));
  check("the same ciphertext cannot be passed off as a different asset (asset ID is bound in)",
        await rejects(() => decryptFile({ dek: e1.dek, iv: e1.iv, ciphertext: e1.ciphertext, assetId: "22222222-2222-4222-8222-222222222222" }),
                      (e) => e.name === "OperationError"));

  // ---- 7. big file + timing for the report ----
  const big = randomBytes(5_000_000);
  const t0 = performance.now();
  const eb = await encryptFile(big, ASSET);
  const t1 = performance.now();
  const cidBig = await ipfs.add(eb.ciphertext);
  const t2 = performance.now();
  const fetched = await fetchVerified(ipfs, cidBig);
  const t3 = performance.now();
  const pb = await decryptFile({ dek: eb.dek, iv: eb.iv, ciphertext: fetched, assetId: ASSET });
  const t4 = performance.now();
  check("a 5 MB file survives the full round trip", sameBytes(pb, big));
  console.log(`INFO  5 MB: encrypt ${(t1 - t0).toFixed(0)} ms | upload ${(t2 - t1).toFixed(0)} ms | fetch+verify ${(t3 - t2).toFixed(0)} ms | decrypt ${(t4 - t3).toFixed(0)} ms`);

  // ---- 8. deleting from IPFS is only a LOCAL, best-effort action ----
  const keepData = await encryptFile(enc.encode("keep me"), ASSET);
  const dropData = await encryptFile(enc.encode("drop me"), ASSET);
  const keepCid = await ipfs.add(keepData.ciphertext);
  const dropCid = await ipfs.add(dropData.ciphertext);
  await ipfs.pinRm(dropCid);
  check("unpinning alone does NOT delete: the data is still readable until garbage collection",
        sameBytes(await ipfs.cat(dropCid), dropData.ciphertext));
  await ipfs.gc();
  check("after unpin + garbage collection the dropped ciphertext is gone from this node",
        await rejects(() => ipfs.cat(dropCid, "3s"), (e) => /not found/i.test(e.message)));
  check("a pinned file survives garbage collection", sameBytes(await ipfs.cat(keepCid), keepData.ciphertext));
  console.log("INFO  on a real IPFS network other nodes may still hold copies, so REAL erasure = destroying the key (crypto-shredding)");
} finally {
  daemon.kill();
  await new Promise((r) => setTimeout(r, 500));
  try { rmSync(repo, { recursive: true, force: true }); } catch { /* the node may still hold files briefly on Windows */ }
}

console.log(failures === 0 ? "\nALL TESTS PASSED" : `\n${failures} TEST(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
