pragma circom 2.1.9;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/eddsaposeidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";

// EPHEMERE age-proof circuit.
// Statement: "I hold a credential, signed by the issuer whose public key is
// (issuerAx, issuerAy), whose date of birth is on or before cutoffDay."
// The date of birth, salt and signature never leave the browser.
template AgeProof() {
    // ---- private inputs (known only to the user) ----
    signal input dob;        // date of birth, days since 1970-01-01
    signal input salt;       // random blinding value inside the credential
    signal input sigS;       // EdDSA signature scalar
    signal input sigR8x;     // EdDSA signature point R8
    signal input sigR8y;

    // ---- public inputs (chosen/checked by the verifier, NOT the prover) ----
    signal input issuerAx;   // issuer public key
    signal input issuerAy;
    signal input cutoffDay;  // verifier computes: today - 18 years, in days
    signal input nonce;      // verifier's fresh per-request challenge (anti-replay)

    // 1. Range-check so the comparator below is sound
    component dobBits = Num2Bits(32);
    dobBits.in <== dob;
    component cutoffBits = Num2Bits(32);
    cutoffBits.in <== cutoffDay;

    // 2. Credential message = Poseidon(dob, salt)
    component msgHash = Poseidon(2);
    msgHash.inputs[0] <== dob;
    msgHash.inputs[1] <== salt;

    // 3. The issuer must have signed exactly this credential
    component sigCheck = EdDSAPoseidonVerifier();
    sigCheck.enabled <== 1;
    sigCheck.Ax <== issuerAx;
    sigCheck.Ay <== issuerAy;
    sigCheck.S <== sigS;
    sigCheck.R8x <== sigR8x;
    sigCheck.R8y <== sigR8y;
    sigCheck.M <== msgHash.out;

    // 4. dob <= cutoffDay  (born early enough to be 18+)
    component old = LessEqThan(32);
    old.in[0] <== dob;
    old.in[1] <== cutoffDay;
    old.out === 1;

    // 5. Bind the proof to this request: forces the nonce into the constraint
    //    system so a proof for one request cannot be replayed for another.
    signal nonceSq;
    nonceSq <== nonce * nonce;
}

component main { public [issuerAx, issuerAy, cutoffDay, nonce] } = AgeProof();
