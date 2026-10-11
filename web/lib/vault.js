// What Asha's browser does with files: encrypt, upload, list, and open again.
import { decryptFile, encryptFile } from "./aes";
import { fromB64, toB64 } from "./bytes";
import { computeCid } from "./cid";
import { getOwnerKeys } from "./keys";
import { wrapDek } from "./pre";
import { apiJson, api, ApiProblem } from "./session";

const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

// Pretend personal data, for the demo only.
export function sampleProfile() {
  return new TextEncoder().encode(JSON.stringify({
    name: "Asha Demo",
    address: "Flat 4B, Rosewood Apartments, Example Road, Bengaluru 560001",
    phone: "+91 90000 00000",
    blood_group: "O+",
  }, null, 2));
}

export async function uploadFile({ label, bytes }) {
  const { U, owner } = await getOwnerKeys();
  const assetId = crypto.randomUUID();
  const { dek, iv, ciphertext } = await encryptFile(bytes, assetId);
  const { capsule, wrappedDek } = wrapDek(U, owner.pk, dek);
  dek.fill(0);
  const expectedCid = await computeCid(ciphertext);
  const out = await apiJson("/api/assets", {
    method: "POST",
    body: JSON.stringify({
      assetId, label,
      iv: toB64(iv), capsule: toB64(capsule.toBytes()), wrappedDek: toB64(wrappedDek),
      ownerPk: toB64(owner.pk.toCompressedBytes()), verifyingPk: toB64(owner.verifyingPk.toCompressedBytes()),
      ciphertext: toB64(ciphertext),
    }),
  });
  if (out.cid !== expectedCid) throw new ApiProblem(0, "CID_MISMATCH", "Storage returned a different address than expected. The file was not trusted.");
  return out;
}

export async function listFiles() {
  return (await apiJson("/api/assets")).assets;
}

// Fetch, CHECK the bytes match the CID, then decrypt in the browser.
export async function openFile(assetId) {
  const meta = await apiJson(`/api/assets/${assetId}`);
  const res = await api(`/api/assets/${assetId}/ciphertext`);
  if (!res.ok) throw new ApiProblem(res.status, "DOWNLOAD_FAILED", "The file could not be fetched from storage.");
  const cipher = new Uint8Array(await res.arrayBuffer());
  const actual = await computeCid(cipher);
  if (actual !== meta.cid) throw new ApiProblem(0, "CID_MISMATCH", "The stored bytes do not match their address, so they were rejected.");

  const { U, owner } = await getOwnerKeys();
  if (toB64(owner.pk.toCompressedBytes()) !== meta.ownerPk) {
    throw new ApiProblem(0, "KEYS_MISSING", "This browser does not hold the keys for this file (the browser data was cleared, or the file was uploaded from another browser).");
  }
  const dek = U.decryptOriginal(owner.sk, U.Capsule.fromBytes(fromB64(meta.capsule)), fromB64(meta.wrappedDek));
  const plain = await decryptFile({ dek, iv: fromB64(meta.iv), ciphertext: cipher, assetId });
  dek.fill(0);
  return { text: new TextDecoder().decode(plain), cid: meta.cid, cidVerified: true, storedPreviewHex: hex(cipher.slice(0, 48)), storedBytes: cipher.length };
}
