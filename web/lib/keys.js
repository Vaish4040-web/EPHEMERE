// The owner's secret keys live ONLY in this browser (localStorage). The server never sees them.
// Known limit: clearing browser data loses the keys, and then the files cannot be opened (no backup yet).
import { fromB64, sha256Hex, toB64 } from "./bytes";
import { loadUmbral, ownerFromKeys } from "./pre";

const KEY = "ephemere.ownerKeys.v1";

async function loadKeys() {
  const U = await loadUmbral();
  let created = false;
  let stored = null;
  try { stored = JSON.parse(localStorage.getItem(KEY) ?? "null"); } catch { stored = null; }
  let sk, signerSk;
  if (stored?.sk && stored?.signerSk) {
    sk = U.SecretKey.fromBEBytes(fromB64(stored.sk));
    signerSk = U.SecretKey.fromBEBytes(fromB64(stored.signerSk));
  } else {
    sk = U.SecretKey.random();
    signerSk = U.SecretKey.random();
    localStorage.setItem(KEY, JSON.stringify({ sk: toB64(sk.toBEBytes()), signerSk: toB64(signerSk.toBEBytes()) }));
    created = true;
  }
  const owner = ownerFromKeys(U, sk, signerSk);
  const fingerprint = (await sha256Hex(owner.pk.toCompressedBytes())).slice(0, 12);
  return { U, owner, created, fingerprint };
}

// Load once per page and share the result, so every part of the page uses the same keys
// (React's development mode runs effects twice; this keeps the answer consistent).
let pending = null;
export function getOwnerKeys() {
  pending ??= loadKeys().catch((e) => { pending = null; throw e; });
  return pending;
}
