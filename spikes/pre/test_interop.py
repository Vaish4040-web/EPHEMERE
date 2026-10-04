"""EPHEMERE PRE spike tests.

The OWNER side runs in JavaScript (owner.mjs, like the browser).
The PROXY and ACCESS SERVICE run in Python (like FastAPI).
If these tests pass, the two languages understand each other's data.

Run:  python test_interop.py
"""
import base64
import json
import os
import subprocess
import sys
import time

from cryptography.exceptions import InvalidTag
from umbral_pre import PublicKey, VerificationError

from server_side import AccessService, Proxy

HERE = os.path.dirname(os.path.abspath(__file__))
b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s)


def owner(cmd, **kw):
    """Call the JavaScript owner (browser) side."""
    r = subprocess.run(["node", "owner.mjs"], cwd=HERE, input=json.dumps({"cmd": cmd, **kw}),
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"owner.mjs {cmd} failed:\n{r.stderr}")
    return json.loads(r.stdout)


failures = 0
def check(name, ok, note=""):
    global failures
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"   ({note})" if note else ""))
    if not ok:
        failures += 1

def raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    except Exception as e:  # wrong kind of error still counts as failure of the check
        print("      unexpected error type:", type(e).__name__, e)
        return False
    return False


# ---------------- setup ----------------
SECRET_FILE = b"Patient report: blood group O+, no allergies. " * 50   # pretend personal file
ASSET = "asset-123"

keys = owner("init")                                  # JS: owner + signer keys
bob = AccessService()                                 # Python: the delegate
owner_pk = PublicKey.from_compressed_bytes(b64d(keys["ownerPk"]))
verifying_pk = PublicKey.from_compressed_bytes(b64d(keys["verifyingPk"]))
bob_pk_b64 = b64e(bob.public_key.to_compressed_bytes())

enc = owner("encryptFile", ownerPk=keys["ownerPk"], assetId=ASSET, plaintextB64=b64e(SECRET_FILE))
capsule_b, wrapped, iv, ct = b64d(enc["capsule"]), b64d(enc["wrappedDek"]), b64d(enc["iv"]), b64d(enc["fileCiphertext"])

def open_with(cfrags, access=bob, capsule=capsule_b, wrapped_dek=wrapped, file_ct=ct):
    return access.open_file(asset_id=ASSET, capsule_b=capsule, cfrags_b=cfrags, wrapped_dek=wrapped_dek,
                            iv=iv, file_ciphertext=file_ct, owner_pk=owner_pk, verifying_pk=verifying_pk)

# ---------------- T1: the owner can still open their own file ----------------
od = owner("ownerDecrypt", ownerSk=keys["ownerSk"], assetId=ASSET, capsule=enc["capsule"],
           wrappedDek=enc["wrappedDek"], iv=enc["iv"], fileCiphertext=enc["fileCiphertext"])
check("owner can decrypt their own file (allowed by design)", b64d(od["plaintextB64"]) == SECRET_FILE)

# ---------------- T2: full flow, JS owner -> Python proxy -> Python access service ----------------
d = owner("delegate", ownerSk=keys["ownerSk"], signerSk=keys["signerSk"], bobPk=bob_pk_b64, threshold=1, shares=1)
proxy = Proxy()
proxy.store("g1", [b64d(k) for k in d["kfrags"]], time.time() + 3600, verifying_pk, owner_pk, bob.public_key)

t0 = time.perf_counter()
cfrags = proxy.reencrypt("g1", capsule_b)
t1 = time.perf_counter()
plain = open_with(cfrags)
t2 = time.perf_counter()
check("INTEROP: JS-made capsule + kfrag work in Python; file recovered exactly", plain == SECRET_FILE,
      f"re-encrypt {1000*(t1-t0):.1f} ms, verify+decrypt {1000*(t2-t1):.1f} ms")
kept_cfrags = cfrags                                   # pretend a careless company kept these

# ---------------- T3: someone else cannot use a stolen cfrag ----------------
eve = AccessService()
check("a different party cannot use the same cfrag", raises(VerificationError, lambda: open_with(cfrags, access=eve)))

# ---------------- T4: tampering is detected ----------------
bad_ct = bytearray(ct); bad_ct[5] ^= 1
check("changed file ciphertext is rejected (AES-GCM tag)", raises(InvalidTag, lambda: open_with(cfrags, file_ct=bytes(bad_ct))))
bad_wrapped = bytearray(wrapped); bad_wrapped[5] ^= 1
check("changed wrapped key is rejected", raises(ValueError, lambda: open_with(cfrags, wrapped_dek=bytes(bad_wrapped))))

# ---------------- T5: revocation ----------------
proxy.revoke("g1")
check("after revoke, proxy refuses to produce cfrags", raises(PermissionError, lambda: proxy.reencrypt("g1", capsule_b)))

check("a revoked grant id cannot be switched back on",
      raises(PermissionError, lambda: proxy.store("g1", [b64d(k) for k in d["kfrags"]], time.time() + 3600,
                                                   verifying_pk, owner_pk, bob.public_key)))
check("a revoked kfrag cannot be re-registered under a NEW grant id",
      raises(PermissionError, lambda: proxy.store("g1-again", [b64d(k) for k in d["kfrags"]], time.time() + 3600,
                                                   verifying_pk, owner_pk, bob.public_key)))

# ---------------- T6: expiry (fake clock) ----------------
now = [1000.0]
p2 = Proxy(clock=lambda: now[0])
p2.store("g2", [b64d(k) for k in d["kfrags"]], 1500.0, verifying_pk, owner_pk, bob.public_key)
ok_before = len(p2.reencrypt("g2", capsule_b)) == 1
now[0] = 1600.0
check("grant works before expiry and is refused after expiry",
      ok_before and raises(PermissionError, lambda: p2.reencrypt("g2", capsule_b)))

# ---------------- T7: honest limit, a company that KEPT cfrags still opens the OLD capsule ----------------
still = open_with(kept_cfrags) == SECRET_FILE
check("LIMIT (expected): cfrags kept before revocation still open the OLD capsule", still,
      "this is why the company must never be handed cfrags; see decision D3")

# ---------------- T8: strong revoke = re-key the file ----------------
enc2 = owner("encryptFile", ownerPk=keys["ownerPk"], assetId=ASSET, plaintextB64=b64e(SECRET_FILE))
capsule2, wrapped2, ct2 = b64d(enc2["capsule"]), b64d(enc2["wrappedDek"]), b64d(enc2["fileCiphertext"])
iv_old = iv
iv = b64d(enc2["iv"])
check("after re-key, the old kept cfrags do NOT open the new capsule",
      raises(VerificationError, lambda: open_with(kept_cfrags, capsule=capsule2, wrapped_dek=wrapped2, file_ct=ct2)))
check("new capsule has a new key (ciphertext differs)", ct2 != ct)
iv = iv_old

# ---------------- T9: threshold 2-of-3 across three proxy nodes ----------------
d3 = owner("delegate", ownerSk=keys["ownerSk"], signerSk=keys["signerSk"], bobPk=bob_pk_b64, threshold=2, shares=3)
nodes = [Proxy() for _ in range(3)]
for node, kf in zip(nodes, d3["kfrags"]):
    node.store("g3", [b64d(kf)], time.time() + 3600, verifying_pk, owner_pk, bob.public_key)
one = nodes[0].reencrypt("g3", capsule_b)
two = one + nodes[1].reencrypt("g3", capsule_b)
check("2-of-3: one node alone cannot open the file", raises(ValueError, lambda: open_with(one)))
check("2-of-3: two nodes together can", open_with(two) == SECRET_FILE)

print("\nALL TESTS PASSED" if failures == 0 else f"\n{failures} TEST(S) FAILED")
sys.exit(0 if failures == 0 else 1)
