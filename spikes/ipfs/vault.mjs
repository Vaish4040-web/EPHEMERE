// EPHEMERE IPFS spike: the "vault" side (this code is what runs in the BROWSER).
//   1. Encrypt a file with a fresh random key (AES-GCM-256, WebCrypto)
//   2. Upload ONLY the ciphertext to IPFS and get its CID (content address)
//   3. Later: fetch by CID, CHECK the bytes really match the CID, then decrypt
// Uses only WebCrypto + fetch + the official IPFS importer. No custom crypto.
import { importBytes } from "ipfs-unixfs-importer";
import { MemoryBlockstore } from "blockstore-core/memory";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

// ------------------------------------------------------------- encryption
export async function encryptFile(plaintext, assetId) {
  const dek = crypto.getRandomValues(new Uint8Array(32));   // new key for every file
  const iv = crypto.getRandomValues(new Uint8Array(12));    // new IV for every encryption
  const key = await subtle.importKey("raw", dek, "AES-GCM", false, ["encrypt"]);
  const ciphertext = new Uint8Array(await subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: enc.encode(assetId) }, key, plaintext));
  return { dek, iv, ciphertext };
}

export async function decryptFile({ dek, iv, ciphertext, assetId }) {
  const key = await subtle.importKey("raw", dek, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(await subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: enc.encode(assetId) }, key, ciphertext));
}

// ------------------------------------------------------------------- CIDs
// Work out the CID of some bytes ourselves, with the same settings we ask the node to use
// (CIDv1, raw leaves, default 256 KiB chunks). If the node ever hands back different bytes,
// the CID will not match and we refuse to use them.
export async function computeCid(bytes) {
  const { cid } = await importBytes(bytes, new MemoryBlockstore(), { cidVersion: 1, rawLeaves: true });
  return cid.toString();
}

// -------------------------------------------------------- IPFS (Kubo RPC)
export class IpfsClient {
  constructor(apiBase) { this.api = apiBase.replace(/\/$/, ""); }

  async #post(path, body) {
    const r = await fetch(`${this.api}/api/v0/${path}`, { method: "POST", body });
    if (!r.ok) throw new Error(`IPFS ${path} failed (${r.status}): ${(await r.text()).slice(0, 200)}`);
    return r;
  }
  async version() { return (await (await this.#post("version")).json()).Version; }

  async add(bytes) {
    const form = new FormData();
    form.append("file", new Blob([bytes]));
    const r = await this.#post("add?cid-version=1&raw-leaves=true&pin=true&quieter=true", form);
    const lines = (await r.text()).trim().split("\n");
    return JSON.parse(lines[lines.length - 1]).Hash;
  }
  async cat(cid, timeout = "5s") {
    const r = await this.#post(`cat?arg=${encodeURIComponent(cid)}&timeout=${timeout}`);
    return new Uint8Array(await r.arrayBuffer());
  }
  async pinRm(cid) { await (await this.#post(`pin/rm?arg=${encodeURIComponent(cid)}`)).text(); }
  async gc() { await (await this.#post("repo/gc")).text(); }
}

// Fetch by CID and make sure we really got what the CID promises.
export async function fetchVerified(client, cid) {
  const bytes = await client.cat(cid);
  const actual = await computeCid(bytes);
  if (actual !== cid) throw new Error(`CID_MISMATCH: asked for ${cid} but the bytes hash to ${actual}`);
  return bytes;
}
