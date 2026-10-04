// EPHEMERE PRE spike: the "owner" side (this code is what runs in the BROWSER).
// For testing, the Python test calls this file as a command-line tool:
//   echo '{"cmd":"init"}' | node owner.mjs
// In the real app the secret keys never leave the browser. Here the test harness
// passes them in and out only so we can test across two languages.
import { createRequire } from "node:module";
import { webcrypto } from "node:crypto";

const require = createRequire(import.meta.url);
const U = require("@nucypher/umbral-pre"); // umbral-pre 0.10.0 (WASM)
const subtle = webcrypto.subtle;            // same WebCrypto API the browser has

const b64 = (u8) => Buffer.from(u8).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const aad = (assetId) => new TextEncoder().encode(assetId);

function init() {
  const sk = U.SecretKey.random();
  const signerSk = U.SecretKey.random(); // separate key used only to sign kfrags
  return {
    ownerSk: b64(sk.toBEBytes()),
    ownerPk: b64(sk.publicKey().toCompressedBytes()),
    signerSk: b64(signerSk.toBEBytes()),
    verifyingPk: b64(new U.Signer(signerSk).verifyingKey().toCompressedBytes()),
  };
}

// 1. Encrypt a file with a fresh random key (DEK), then wrap the DEK with Umbral.
async function encryptFile({ ownerPk, assetId, plaintextB64 }) {
  const pk = U.PublicKey.fromCompressedBytes(unb64(ownerPk));
  const dek = webcrypto.getRandomValues(new Uint8Array(32));   // new key per file
  const iv = webcrypto.getRandomValues(new Uint8Array(12));    // new IV per encryption
  const key = await subtle.importKey("raw", dek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad(assetId) }, key, unb64(plaintextB64)));
  const [capsule, wrappedDek] = U.encrypt(pk, dek);
  dek.fill(0);
  return { iv: b64(iv), fileCiphertext: b64(ct), capsule: b64(capsule.toBytes()), wrappedDek: b64(wrappedDek) };
}

// 2. The owner can always decrypt their own file (this is allowed by design).
async function ownerDecrypt({ ownerSk, assetId, capsule, wrappedDek, iv, fileCiphertext }) {
  const sk = U.SecretKey.fromBEBytes(unb64(ownerSk));
  const dek = U.decryptOriginal(sk, U.Capsule.fromBytes(unb64(capsule)), unb64(wrappedDek));
  const key = await subtle.importKey("raw", dek, "AES-GCM", false, ["decrypt"]);
  const pt = new Uint8Array(await subtle.decrypt(
    { name: "AES-GCM", iv: unb64(iv), additionalData: aad(assetId) }, key, unb64(fileCiphertext)));
  dek.fill(0);
  return { plaintextB64: b64(pt) };
}

// 3. Give the access service permission: make key fragments (kfrags) for it.
function delegate({ ownerSk, signerSk, bobPk, threshold, shares }) {
  const sk = U.SecretKey.fromBEBytes(unb64(ownerSk));
  const signer = new U.Signer(U.SecretKey.fromBEBytes(unb64(signerSk)));
  const bob = U.PublicKey.fromCompressedBytes(unb64(bobPk));
  const kfrags = U.generateKFrags(sk, bob, signer, threshold, shares, true, true);
  return { kfrags: kfrags.map((k) => b64(k.toBytes())) };
}

const commands = { init, encryptFile, ownerDecrypt, delegate };

let input = "";
for await (const chunk of process.stdin) input += chunk;
const req = JSON.parse(input);
const fn = commands[req.cmd];
if (!fn) { console.error("unknown cmd " + req.cmd); process.exit(2); }
console.log(JSON.stringify(await fn(req)));
