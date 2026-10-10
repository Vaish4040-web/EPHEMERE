// Small helpers for turning bytes into text (base64) and back. Browser-safe.
export function toB64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
export function fromB64(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
export async function sha256Hex(u8) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", u8));
  return Array.from(h, (b) => b.toString(16).padStart(2, "0")).join("");
}
