# EPHEMERE: ZK spike (Member A)

Proves **"I am 18 or older"** without revealing the date of birth.

## What the circuit proves (`age_proof.circom`)
1. The user holds a credential `Poseidon(dob, salt)` **signed by the issuer** (EdDSA-Poseidon, BabyJubJub), checked *inside* the circuit.
2. `dob <= cutoffDay` (cutoff = today minus 18 years, computed by the **verifier**).
3. The proof is bound to a verifier-chosen `nonce` (anti-replay).

| | Signals |
|---|---|
| Private (never leave the browser) | `dob`, `salt`, signature (`S`, `R8x`, `R8y`) |
| Public (the verifier supplies and checks them) | `issuerAx`, `issuerAy`, `cutoffDay`, `nonce` |

**Verifier rule (important):** after `groth16.verify`, also check that the public signals equal what *you* asked for (your issuer key, your cutoff, your nonce). A valid proof for someone else's cutoff or nonce is not valid for you. `test_age_proof.mjs` shows this.

## Run it
```bash
npm install
# Circom compiler: download the binary for your OS from
#   https://github.com/iden3/circom/releases  (tested with v2.1.9) and save it as ./circom
#   Linux: curl -L -o circom https://github.com/iden3/circom/releases/download/v2.1.9/circom-linux-amd64 && chmod +x circom
./build.sh                  # compile + dev trusted setup (phase 2 takes several minutes)
node test_age_proof.mjs     # end-to-end + attack tests
```

## Tested results (cloud sandbox, Node 22)
- 4,544 constraints, 4 public inputs, 5 private inputs
- Proof generation about 1.8 s (Node), verification about 30 ms, proof about 724 bytes of JSON
- All 6 tests pass: honest adult; replayed proof rejected; 15-year-old cannot prove; forged issuer signature cannot prove; edited dob cannot prove; wrong issuer key rejected

Browser proving time will differ. Measure it yourselves for the report.

## Limits to state in your report
- **Trusted setup is dev-only.** `build.sh` makes its own powers of tau, which is fine for a demo but not production. Say so, and cite the public Hermez/Perpetual Powers of Tau ceremony as the production alternative.
- **The issuer is simulated.** In reality a trusted authority issues the credential. Your demo's issuer is a script. Be explicit about this.
- **The issuer key is public.** The verifier learns which issuer signed the credential, and nothing else about the user.
- **Keep it unlinkable.** Proofs reveal only the four public signals. Never expose `dob`, `salt` or the signature as public inputs, and use a fresh random `salt` per credential.

## Next steps
1. Run the proof in the **browser** (`snarkjs.groth16.fullProve` with the `.wasm` and `.zkey` served as static files) and record the time.
2. Decide with Member C how FastAPI verifies proofs: call `snarkjs` from a Node subprocess, or use a Python Groth16 verifier.
3. Define the proof/public-signal JSON format in the interface contract.
4. Add a second circuit later (for example residency) only if time remains.
