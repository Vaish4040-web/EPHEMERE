// Copies the compiled circuit + keys into the web app and creates two test credentials
// signed by a simulated issuer (one adult, one 15-year-old).
//   Usage (inside circuits/):  npm run zk:prepare          (run ./build.sh first)
import { buildEddsa, buildPoseidon } from "circomlibjs";
import { copyFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";

const out = process.argv[2] ?? join("..", "web", "public", "zk");
const need = [
  ["build/age_proof_js/age_proof.wasm", "age_proof.wasm"],
  ["keys/age_final.zkey", "age_final.zkey"],
  ["keys/verification_key.json", "verification_key.json"],
];
for (const [src] of need) {
  if (!existsSync(src)) { console.error(`Missing ${src}. Run ./build.sh first.`); process.exit(1); }
}
mkdirSync(out, { recursive: true });
for (const [src, name] of need) copyFileSync(src, join(out, name));

const eddsa = await buildEddsa();
const poseidon = await buildPoseidon();
const F = poseidon.F;
const issuerPriv = randomBytes(32);
const issuerPub = eddsa.prv2pub(issuerPriv);
const day = (y, m, d) => Math.floor(Date.UTC(y, m, d) / 86_400_000);

function credential(dobDay) {
  const salt = BigInt("0x" + randomBytes(16).toString("hex"));
  const sig = eddsa.signPoseidon(issuerPriv, poseidon([BigInt(dobDay), salt]));
  return {
    dobDay,
    salt: salt.toString(),
    sig: { S: sig.S.toString(), R8x: F.toObject(sig.R8[0]).toString(), R8y: F.toObject(sig.R8[1]).toString() },
    issuerPub: { Ax: F.toObject(issuerPub[0]).toString(), Ay: F.toObject(issuerPub[1]).toString() },
  };
}
const now = new Date();
writeFileSync(join(out, "credential.json"), JSON.stringify(credential(day(2000, 5, 15)), null, 2));
writeFileSync(join(out, "credential_minor.json"), JSON.stringify(credential(day(now.getUTCFullYear() - 15, 0, 1)), null, 2));
console.log(`Wrote proof files and test credentials to ${out}`);
