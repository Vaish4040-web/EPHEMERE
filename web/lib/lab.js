// The browser self-test. Every check runs inside the real browser and reports PASS, FAIL or SKIP.
import { encryptFile, decryptFile } from "./aes";
import { fromB64, sameBytes, sha256Hex, toB64 } from "./bytes";
import { delegateOpen, loadUmbral, makeKfrags, newOwner, proxyReencrypt, wrapDek } from "./pre";
import { loadJson, loadSnarkjs, missingZkFiles, newChallenge, prove, verify, zkFiles } from "./zk";

const enc = new TextEncoder();
const ASSET = "11111111-1111-4111-8111-111111111111";
const OTHER_ASSET = "22222222-2222-4222-8222-222222222222";

export async function runAllChecks(report) {
  const results = [];
  const run = async (group, name, fn) => {
    const t0 = performance.now();
    let status = "PASS";
    let note = "";
    try {
      const r = await fn();
      if (r === false) status = "FAIL";
      else if (typeof r === "string") note = r;
      else if (r && r.skip) { status = "SKIP"; note = r.skip; }
    } catch (e) {
      status = "FAIL";
      note = String(e?.message ?? e).slice(0, 220);
    }
    results.push({ group, name, status, note, ms: Math.round(performance.now() - t0) });
    report([...results]);
  };
  const failsWith = async (fn, test = () => true) => {
    try { await fn(); } catch (e) { return test(e); }
    return false;
  };

  // ------------------------------------------------------------ 1. the browser itself
  const G1 = "1. This browser";
  await run(G1, "page is a secure context (WebCrypto needs this)", () => window.isSecureContext);
  await run(G1, "WebCrypto, WebAssembly and Web Workers are available", () =>
    typeof crypto?.subtle === "object" && typeof WebAssembly === "object" && typeof Worker === "function"
      ? `${navigator.hardwareConcurrency} CPU threads; ${navigator.userAgent.match(/(Chrome|Firefox|Edg|Safari)\/[\d.]+/)?.[0] ?? "unknown browser"}`
      : false);

  // ------------------------------------------------------------ 2. AES-GCM
  const G2 = "2. File encryption (AES-GCM-256)";
  const secret = enc.encode("Patient report: blood group O+, no allergies. ".repeat(100));
  let e1;
  await run(G2, "encrypt then decrypt returns the original file", async () => {
    e1 = await encryptFile(secret, ASSET);
    return sameBytes(await decryptFile({ ...e1, assetId: ASSET }), secret);
  });
  await run(G2, "encrypting the same file twice gives a different IV and ciphertext", async () => {
    const e2 = await encryptFile(secret, ASSET);
    return !sameBytes(e1.iv, e2.iv) && !sameBytes(e1.ciphertext, e2.ciphertext);
  });
  await run(G2, "changing a single bit is rejected", async () => {
    const bad = e1.ciphertext.slice(); bad[5] ^= 1;
    return failsWith(() => decryptFile({ ...e1, ciphertext: bad, assetId: ASSET }), (e) => e.name === "OperationError");
  });
  await run(G2, "the ciphertext cannot be passed off as a different asset", () =>
    failsWith(() => decryptFile({ ...e1, assetId: OTHER_ASSET }), (e) => e.name === "OperationError"));

  // ------------------------------------------------------------ 3. Proxy re-encryption
  const G3 = "3. Sharing a file (Umbral proxy re-encryption)";
  let U;
  await run(G3, "the Umbral WebAssembly library loads in this browser", async () => {
    U = await loadUmbral();
    return typeof U.encrypt === "function" && typeof U.generateKFrags === "function";
  });
  if (U) {
    const owner = newOwner(U);
    const delegateSk = U.SecretKey.random();
    const file = await encryptFile(secret, ASSET);
    const { capsule, wrappedDek } = wrapDek(U, owner.pk, file.dek);

    await run(G3, "the owner can open their own wrapped key", () =>
      sameBytes(U.decryptOriginal(owner.sk, capsule, wrappedDek), file.dek));

    await run(G3, "full flow: owner shares, proxy re-encrypts, delegate recovers the key and opens the file", async () => {
      const t0 = performance.now();
      const kfrags = makeKfrags(U, owner, delegateSk.publicKey(), 1, 1);
      const t1 = performance.now();
      const cfrags = kfrags.map((k) => proxyReencrypt(U, capsule, k));
      const t2 = performance.now();
      const dek = delegateOpen(U, { delegateSk, ownerPk: owner.pk, verifyingPk: owner.verifyingPk, capsule, cfrags, wrappedDek });
      const plain = await decryptFile({ dek, iv: file.iv, ciphertext: file.ciphertext, assetId: ASSET });
      const t3 = performance.now();
      return sameBytes(plain, secret)
        ? `make kfrags ${(t1 - t0).toFixed(1)} ms, re-encrypt ${(t2 - t1).toFixed(1)} ms, verify+decrypt ${(t3 - t2).toFixed(1)} ms`
        : false;
    });

    const kf = makeKfrags(U, owner, delegateSk.publicKey(), 1, 1);
    const cf = kf.map((k) => proxyReencrypt(U, capsule, k));
    await run(G3, "a different party cannot use the same cfrag", () =>
      failsWith(() => delegateOpen(U, { delegateSk: U.SecretKey.random(), ownerPk: owner.pk, verifyingPk: owner.verifyingPk, capsule, cfrags: cf, wrappedDek })));
    await run(G3, "cfrags that were not signed by this owner are rejected", () =>
      failsWith(() => delegateOpen(U, { delegateSk, ownerPk: owner.pk, verifyingPk: newOwner(U).verifyingPk, capsule, cfrags: cf, wrappedDek })));

    await run(G3, "2-of-3: one proxy alone cannot open the file, two together can", async () => {
      const k3 = makeKfrags(U, owner, delegateSk.publicKey(), 2, 3);
      const c3 = k3.map((k) => proxyReencrypt(U, capsule, k));
      const one = await failsWith(() => delegateOpen(U, { delegateSk, ownerPk: owner.pk, verifyingPk: owner.verifyingPk, capsule, cfrags: [c3[0]], wrappedDek }));
      const dek = delegateOpen(U, { delegateSk, ownerPk: owner.pk, verifyingPk: owner.verifyingPk, capsule, cfrags: [c3[0], c3[1]], wrappedDek });
      return one && sameBytes(dek, file.dek);
    });
  } else {
    for (const n of ["owner opens own key", "full sharing flow", "different party rejected", "unsigned cfrags rejected", "2-of-3"]) {
      results.push({ group: G3, name: n, status: "SKIP", note: "Umbral did not load", ms: 0 });
    }
    report([...results]);
  }

  // ------------------------------------------------------------ 4. Zero-knowledge proof
  const G4 = "4. Zero-knowledge age proof (Circom + snarkjs)";
  let snarkjs;
  await run(G4, "snarkjs loads in this browser", async () => { snarkjs = await loadSnarkjs(); return typeof snarkjs?.groth16?.fullProve === "function"; });
  let missing = [];
  await run(G4, "proof files from the circuits folder are present", async () => {
    missing = await missingZkFiles();
    return missing.length === 0 ? true : { skip: `missing: ${missing.join(", ")}. In the circuits folder run: npm run zk:prepare` };
  });
  const SKIP = { skip: "needs the proof files (see the check above)" };
  if (snarkjs && missing.length === 0) {
    const vkey = await loadJson(zkFiles.vkey);
    const adult = await loadJson(zkFiles.adult);
    const minor = await loadJson(zkFiles.minor);
    const challenge = newChallenge();
    let out;
    await run(G4, "an adult's proof is created and verified in the browser", async () => {
      const t0 = performance.now();
      out = await prove(snarkjs, adult, challenge);
      const t1 = performance.now();
      const v = await verify(snarkjs, vkey, out, challenge, adult.issuerPub);
      const t2 = performance.now();
      return v.proofOk ? `PROVE ${(t1 - t0).toFixed(0)} ms, VERIFY ${(t2 - t1).toFixed(0)} ms, proof ${JSON.stringify(out.proof).length} bytes` : false;
    });
    await run(G4, "the proof carries exactly the verifier's issuer key, cutoff and nonce", async () =>
      (await verify(snarkjs, vkey, out, challenge, adult.issuerPub)).signalsMatch);
    await run(G4, "the date of birth and salt are NOT among the public values", () =>
      !out.publicSignals.includes(String(adult.dobDay)) && !out.publicSignals.includes(adult.salt));
    await run(G4, "a 15-year-old cannot create a proof", () => failsWith(() => prove(snarkjs, minor, challenge)));
    await run(G4, "an old proof is rejected for a new request (replay)", async () => {
      const v = await verify(snarkjs, vkey, out, newChallenge(), adult.issuerPub);
      return !v.signalsMatch;
    });
  } else {
    for (const n of ["adult proof created and verified", "challenge values in the proof", "no personal values in public signals", "minor cannot prove", "replay rejected"]) {
      results.push({ group: G4, name: n, status: "SKIP", note: SKIP.skip, ms: 0 });
    }
    report([...results]);
  }

  const summary = {
    pass: results.filter((r) => r.status === "PASS").length,
    fail: results.filter((r) => r.status === "FAIL").length,
    skip: results.filter((r) => r.status === "SKIP").length,
  };
  return { results, summary };
}

// ---- Optional manual step: make a bundle for the Python server side to open (cross-language test) ----
export async function createShareBundle(bobPublicKeyB64) {
  const U = await loadUmbral();
  const bobPk = U.PublicKey.fromCompressedBytes(fromB64(bobPublicKeyB64.trim()));
  const owner = newOwner(U);
  const plaintext = enc.encode("EPHEMERE browser interop test file. ".repeat(40));
  const assetId = crypto.randomUUID();
  const { dek, iv, ciphertext } = await encryptFile(plaintext, assetId);
  const { capsule, wrappedDek } = wrapDek(U, owner.pk, dek);
  const kfrags = makeKfrags(U, owner, bobPk, 1, 1);
  dek.fill(0);
  return {
    assetId,
    ownerPk: toB64(owner.pk.toCompressedBytes()),
    verifyingPk: toB64(owner.verifyingPk.toCompressedBytes()),
    iv: toB64(iv),
    fileCiphertext: toB64(ciphertext),
    capsule: toB64(capsule.toBytes()),
    wrappedDek: toB64(wrappedDek),
    kfrags: kfrags.map((k) => toB64(k.toBytes())),
    plaintextSha256: await sha256Hex(plaintext),
  };
}
