// Zero-knowledge age proof in the browser with snarkjs (loaded as a plain <script>).
// The page plays two roles for testing: the USER (makes the proof) and the VERIFIER (middleware).
const FILES = {
  wasm: "/zk/age_proof.wasm",
  zkey: "/zk/age_final.zkey",
  vkey: "/zk/verification_key.json",
  adult: "/zk/credential.json",
  minor: "/zk/credential_minor.json",
};

export async function loadSnarkjs() {
  if (window.snarkjs) return window.snarkjs;
  await new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "/vendor/snarkjs.min.js";
    s.onload = resolve;
    s.onerror = () => reject(new Error("Could not load /vendor/snarkjs.min.js. Run: npm run prepare:web"));
    document.head.appendChild(s);
  });
  return window.snarkjs;
}

// Are the files from the circuits folder present? (npm run zk:prepare in the circuits folder creates them)
export async function missingZkFiles() {
  const missing = [];
  for (const url of Object.values(FILES)) {
    const r = await fetch(url, { method: "HEAD" });
    if (!r.ok) missing.push(url);
  }
  return missing;
}

export const loadJson = async (url) => (await fetch(url)).json();
export const zkFiles = FILES;

// The VERIFIER decides the challenge: cutoff day (today minus 18 years) and a fresh random nonce.
export function newChallenge() {
  const t = new Date();
  const cutoff = Date.UTC(t.getUTCFullYear() - 18, t.getUTCMonth(), t.getUTCDate());
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = BigInt("0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(""));
  return { cutoffDay: Math.floor(cutoff / 86_400_000), nonce: nonce.toString() };
}

// The USER builds the proof from their credential. dob, salt and signature never leave this function.
export async function prove(snarkjs, cred, challenge) {
  const input = {
    dob: String(cred.dobDay),
    salt: cred.salt,
    sigS: cred.sig.S,
    sigR8x: cred.sig.R8x,
    sigR8y: cred.sig.R8y,
    issuerAx: cred.issuerPub.Ax,
    issuerAy: cred.issuerPub.Ay,
    cutoffDay: String(challenge.cutoffDay),
    nonce: challenge.nonce,
  };
  return snarkjs.groth16.fullProve(input, FILES.wasm, FILES.zkey);
}

// The VERIFIER checks the proof AND that the public signals are exactly what it asked for.
export async function verify(snarkjs, vkey, { proof, publicSignals }, challenge, issuerPub) {
  const expected = [issuerPub.Ax, issuerPub.Ay, String(challenge.cutoffDay), challenge.nonce];
  const signalsMatch = expected.every((v, i) => publicSignals[i] === v);
  const proofOk = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  return { proofOk, signalsMatch };
}
