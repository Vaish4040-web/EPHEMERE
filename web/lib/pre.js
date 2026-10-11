// Proxy Re-Encryption in the browser with umbral-pre (WebAssembly).
// The library is loaded only when needed, in the browser, never on the server.
let umbralPromise;
export function loadUmbral() {
  umbralPromise ??= import("@nucypher/umbral-pre");
  return umbralPromise;
}

// An owner = an encryption key pair + a separate signing key used only to sign kfrags.
export function ownerFromKeys(U, sk, signerSk) {
  const signer = new U.Signer(signerSk);
  return { sk, pk: sk.publicKey(), signer, verifyingPk: signer.verifyingKey() };
}

export function newOwner(U) {
  return ownerFromKeys(U, U.SecretKey.random(), U.SecretKey.random());
}

// Hide the file key (DEK) so only the owner can open it, for now.
export function wrapDek(U, ownerPk, dek) {
  const [capsule, wrappedDek] = U.encrypt(ownerPk, dek);
  return { capsule, wrappedDek };
}

// Make the permission pieces (kfrags) for one delegate. m-of-n: any m pieces are enough.
export function makeKfrags(U, owner, delegatePk, m = 1, n = 1) {
  return U.generateKFrags(owner.sk, delegatePk, owner.signer, m, n, true, true);
}

// This is what the PROXY does (on the server in the real app). It never sees keys or files.
export function proxyReencrypt(U, capsule, verifiedKfrag) {
  return U.reencrypt(capsule, verifiedKfrag);
}

// This is what the DELEGATE (access service) does: check every cfrag, then recover the file key.
export function delegateOpen(U, { delegateSk, ownerPk, verifyingPk, capsule, cfrags, wrappedDek }) {
  const delegatePk = delegateSk.publicKey();
  const verified = cfrags.map((c) => {
    const cf = U.CapsuleFrag.fromBytes(c.toBytes());   // cross a "wire": serialize, then parse again
    return cf.verify(capsule, verifyingPk, ownerPk, delegatePk);
  });
  return U.decryptReencrypted(delegateSk, ownerPk, capsule, verified, wrappedDek);
}
