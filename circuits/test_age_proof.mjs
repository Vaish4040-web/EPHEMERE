// EPHEMERE ZK spike: issuer -> user (prover) -> verifier, plus attack cases.
// Run: node test_age_proof.mjs
import * as snarkjs from "snarkjs";
import { buildEddsa, buildPoseidon } from "circomlibjs";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";

const WASM = "build/age_proof_js/age_proof.wasm";
const ZKEY = "keys/age_final.zkey";
const VKEY = JSON.parse(readFileSync("keys/verification_key.json", "utf8"));

const DAY_MS = 86_400_000;
const toDay = (d) => Math.floor(d.getTime() / DAY_MS);

const eddsa = await buildEddsa();
const poseidon = await buildPoseidon();
const F = poseidon.F;

// ---------- ISSUER (simulated government / university) ----------
const issuerPriv = randomBytes(32);
const issuerPub = eddsa.prv2pub(issuerPriv); // [Ax, Ay]

function issueCredential(dobDay) {
  const salt = BigInt("0x" + randomBytes(16).toString("hex"));
  const msg = poseidon([BigInt(dobDay), salt]);
  const sig = eddsa.signPoseidon(issuerPriv, msg);
  return { dobDay, salt, sig };
}

// ---------- VERIFIER (EPHEMERE middleware) decides the public inputs ----------
function verifierChallenge() {
  const t = new Date();
  const cutoff = new Date(Date.UTC(t.getUTCFullYear() - 18, t.getUTCMonth(), t.getUTCDate()));
  return {
    cutoffDay: toDay(cutoff),
    nonce: BigInt("0x" + randomBytes(16).toString("hex")),
  };
}

// ---------- USER (browser) builds the proof ----------
async function prove(cred, ch, pub = issuerPub) {
  const input = {
    dob: cred.dobDay.toString(),
    salt: cred.salt.toString(),
    sigS: cred.sig.S.toString(),
    sigR8x: F.toObject(cred.sig.R8[0]).toString(),
    sigR8y: F.toObject(cred.sig.R8[1]).toString(),
    issuerAx: F.toObject(pub[0]).toString(),
    issuerAy: F.toObject(pub[1]).toString(),
    cutoffDay: ch.cutoffDay.toString(),
    nonce: ch.nonce.toString(),
  };
  return snarkjs.groth16.fullProve(input, WASM, ZKEY);
}

// Verifier checks the proof AND that the public signals are the ones it asked for.
async function verify({ proof, publicSignals }, ch, pub = issuerPub) {
  const expected = [
    F.toObject(pub[0]).toString(),
    F.toObject(pub[1]).toString(),
    ch.cutoffDay.toString(),
    ch.nonce.toString(),
  ];
  const signalsMatch = expected.every((v, i) => publicSignals[i] === v);
  const proofOk = await snarkjs.groth16.verify(VKEY, publicSignals, proof);
  return { proofOk, signalsMatch };
}

let failures = 0;
const check = (name, ok) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) failures++;
};

// ---- Test 1: honest adult ----
{
  const cred = issueCredential(toDay(new Date(Date.UTC(2000, 5, 15))));
  const ch = verifierChallenge();
  const t0 = performance.now();
  const out = await prove(cred, ch);
  const t1 = performance.now();
  const v = await verify(out, ch);
  const t2 = performance.now();
  check("honest adult: proof verifies and signals match", v.proofOk && v.signalsMatch);
  console.log(`      prove ${(t1 - t0).toFixed(0)} ms | verify ${(t2 - t1).toFixed(0)} ms | proof JSON ${JSON.stringify(out.proof).length} bytes`);
  console.log(`      public signals: ${out.publicSignals.length} (dob, salt, signature NOT among them)`);

  // ---- Test 2: replay. Old proof against a NEW request's nonce ----
  const ch2 = verifierChallenge();
  const v2 = await verify(out, ch2);
  check("replay of old proof against new nonce is rejected", !v2.signalsMatch);
}

// ---- Test 3: minor cannot produce a proof ----
{
  const t = new Date();
  const minorDob = toDay(new Date(Date.UTC(t.getUTCFullYear() - 15, 0, 1)));
  const cred = issueCredential(minorDob);
  let rejected = false;
  try { await prove(cred, verifierChallenge()); } catch { rejected = true; }
  check("15-year-old cannot generate a proof", rejected);
}

// ---- Test 4: forged credential (user signs with own key) ----
{
  const fakeIssuerPriv = randomBytes(32);
  const dobDay = toDay(new Date(Date.UTC(1990, 0, 1)));
  const salt = 12345n;
  const sig = eddsa.signPoseidon(fakeIssuerPriv, poseidon([BigInt(dobDay), salt]));
  let rejected = false;
  try { await prove({ dobDay, salt, sig }, verifierChallenge()); } catch { rejected = true; }
  check("credential signed by a non-issuer key cannot generate a proof", rejected);
}

// ---- Test 5: tampered dob (user edits dob after issuance) ----
{
  const real = issueCredential(toDay(new Date(Date.UTC(2015, 0, 1)))); // a child
  let rejected = false;
  try {
    await prove({ ...real, dobDay: toDay(new Date(Date.UTC(1990, 0, 1))) }, verifierChallenge());
  } catch { rejected = true; }
  check("editing dob after issuance breaks the signature check", rejected);
}

// ---- Test 6: proof checked against a different issuer key ----
{
  const cred = issueCredential(toDay(new Date(Date.UTC(1995, 0, 1))));
  const ch = verifierChallenge();
  const out = await prove(cred, ch);
  const otherPub = eddsa.prv2pub(randomBytes(32));
  const v = await verify(out, ch, otherPub);
  check("proof does not verify under a different issuer public key", !v.signalsMatch);
}

console.log(failures === 0 ? "\nALL TESTS PASSED" : `\n${failures} TEST(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
