"""EPHEMERE PRE spike: the SERVER side.

Two separate roles (they will be two separate FastAPI apps later):
  * Proxy         holds key fragments (kfrags). It can turn a capsule into a
                  capsule fragment (cfrag) but it can NEVER read the file.
  * AccessService is the "delegate". It collects cfrags, recovers the file key,
                  decrypts INSIDE MEMORY, and returns the plaintext to the caller.
The organization never receives kfrags, cfrags or keys.
"""
import hashlib
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from umbral_pre import (
    Capsule, CapsuleFrag, KeyFrag, PublicKey, SecretKey,
    decrypt_reencrypted, reencrypt,
)


class Proxy:
    """Stores kfrags per grant and enforces revocation and expiry."""

    def __init__(self, clock=time.time):
        self._policies = {}
        self._revoked_digests = set()   # fingerprints of revoked kfrags (a "do not accept again" list)
        self._clock = clock

    def store(self, grant_id, kfrag_bytes_list, expires_at,
              verifying_pk, delegating_pk, receiving_pk):
        # A revoked grant can never be switched back on, and a revoked kfrag can never be
        # re-registered under a new grant id.
        existing = self._policies.get(grant_id)
        if existing is not None and existing["revoked"]:
            raise PermissionError("GRANT_REVOKED")
        digests = [hashlib.sha256(b).hexdigest() for b in kfrag_bytes_list]
        if any(d in self._revoked_digests for d in digests):
            raise PermissionError("KFRAG_REVOKED")
        # Check every kfrag is genuinely signed by the owner for this delegate.
        verified = [KeyFrag.from_bytes(b).verify(verifying_pk, delegating_pk, receiving_pk)
                    for b in kfrag_bytes_list]
        self._policies[grant_id] = {"kfrags": verified, "digests": digests,
                                    "expires_at": expires_at, "revoked": False}

    def revoke(self, grant_id):
        p = self._policies.get(grant_id)
        if p:
            self._revoked_digests.update(p["digests"])   # remember them so they cannot come back
            p["kfrags"] = []                              # delete the key fragments
            p["revoked"] = True

    def reencrypt(self, grant_id, capsule_bytes):
        p = self._policies.get(grant_id)
        if p is None:
            raise PermissionError("NOT_FOUND")
        if p["revoked"]:
            raise PermissionError("GRANT_REVOKED")
        if self._clock() >= p["expires_at"]:
            raise PermissionError("GRANT_EXPIRED")
        capsule = Capsule.from_bytes(capsule_bytes)
        return [bytes(reencrypt(capsule, kf)) for kf in p["kfrags"]]


class AccessService:
    """The delegate. Holds its own Umbral secret key."""

    def __init__(self, secret_key=None):
        # In tests a key can be passed in; otherwise a new random one is made.
        self._sk = secret_key if secret_key is not None else SecretKey.random()
        self.public_key = self._sk.public_key()

    def open_file(self, *, asset_id, capsule_b, cfrags_b, wrapped_dek,
                  iv, file_ciphertext, owner_pk, verifying_pk):
        capsule = Capsule.from_bytes(capsule_b)
        # Every cfrag is checked: it must belong to THIS capsule and THIS delegate.
        vcfrags = [CapsuleFrag.from_bytes(c).verify(capsule, verifying_pk, owner_pk, self.public_key)
                   for c in cfrags_b]
        dek = decrypt_reencrypted(self._sk, owner_pk, capsule, vcfrags, wrapped_dek)
        # Plaintext exists only in this local variable, then the caller uses it and drops it.
        return AESGCM(bytes(dek)).decrypt(iv, file_ciphertext, asset_id.encode())
