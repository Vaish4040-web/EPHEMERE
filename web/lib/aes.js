// AES-GCM-256 with the browser's built-in WebCrypto. A fresh random key and IV for every file.
// The asset ID is bound in as "additional data", so a ciphertext cannot be passed off as another asset.
const enc = new TextEncoder();

export async function encryptFile(plaintext, assetId) {
  const dek = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["encrypt"]);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(assetId) }, key, plaintext)
  );
  return { dek, iv, ciphertext };
}

export async function decryptFile({ dek, iv, ciphertext, assetId }) {
  const key = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: enc.encode(assetId) }, key, ciphertext)
  );
}
