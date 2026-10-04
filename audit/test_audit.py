"""EPHEMERE audit log tests.   Run:  python test_audit.py"""
import json
import os
import sys
import tempfile
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import merkle
from auditlog import (
    AuditCorruption, AuditLog, verify_consistency_proof, verify_event_matches_leaf,
    verify_inclusion_proof, verify_signed_checkpoint,
)

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
    except Exception as e:
        print("      unexpected error:", type(e).__name__, e)
        return False
    return False


uid = lambda: str(uuid.uuid4())
ORG, GRANT, ASSET = uid(), uid(), uid()
tmp = tempfile.TemporaryDirectory()
P = lambda name: os.path.join(tmp.name, name)


def fixed_clock():
    t = [1_700_000_000.0]
    def tick():
        t[0] += 1
        return t[0]
    return tick


def fill(path, n, flip_at=None, key=None):
    """Create a log with n events. If flip_at is set, that event gets a different decision (used to forge)."""
    log = AuditLog(path, signing_key=key, clock=fixed_clock())
    for i in range(n):
        allow = (i % 2 == 0)
        if flip_at == i:
            allow = not allow
        log.append(type="ACCESS_ALLOWED" if allow else "ACCESS_DENIED", org_id=ORG, grant_id=GRANT,
                   asset_id=ASSET, decision="allow" if allow else "deny", reason="OK" if allow else "GRANT_REVOKED")
    return log


def lines(path):
    with open(path, encoding="utf-8") as f:
        return f.read().splitlines()


def write_lines(path, ls):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(ls) + "\n")


# ============ A. Merkle tree maths ============
vec_in = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]
vec_root = ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"]
vl = [merkle.leaf_hash(bytes.fromhex(x)) for x in vec_in]
check("Merkle roots match the published RFC 6962 test vectors (1 to 8 leaves)",
      all(merkle.root_of(vl, 0, n).hex() == vec_root[n - 1] for n in range(1, 9)))

N = 40
leaves = [merkle.leaf_hash(f"event-{i}".encode()) for i in range(N)]
ok_all, ok_neg = True, True
for n in range(1, N + 1):
    root = merkle.root_of(leaves, 0, n)
    for i in range(n):
        path = merkle.inclusion_path(leaves[:n], i)
        ok_all &= merkle.verify_inclusion(leaves[i], i, n, path, root)
        if n > 1:
            ok_neg &= not merkle.verify_inclusion(leaves[i], (i + 1) % n, n, path, root)       # wrong position
            ok_neg &= not merkle.verify_inclusion(merkle.leaf_hash(b"fake"), i, n, path, root)  # wrong content
            bad = list(path); bad[0] = merkle.leaf_hash(b"x")
            ok_neg &= not merkle.verify_inclusion(leaves[i], i, n, bad, root)                  # altered proof
check("inclusion proofs verify for EVERY position in every tree size 1 to 40", ok_all)
check("inclusion proofs fail for wrong position, wrong content or altered path", ok_neg)

ok_all, ok_neg = True, True
for n in range(0, N + 1):
    new_root = merkle.root_of(leaves, 0, n)
    for m in range(0, n + 1):
        old_root = merkle.root_of(leaves, 0, m)
        proof = merkle.consistency_path(leaves, m, n)
        ok_all &= merkle.verify_consistency(m, n, old_root, new_root, proof)
        if 0 < m < n:
            ok_neg &= not merkle.verify_consistency(m, n, merkle.leaf_hash(b"forged"), new_root, proof)
            bad = list(proof); bad[-1] = merkle.leaf_hash(b"x")
            ok_neg &= not merkle.verify_consistency(m, n, old_root, new_root, bad)
check("consistency proofs verify for EVERY pair of sizes (old <= new <= 40)", ok_all)
check("consistency proofs fail if the old root is forged or the proof is altered", ok_neg)

# ============ B. The log: basics and privacy rules ============
key = Ed25519PrivateKey.generate()
log = fill(P("a.jsonl"), 10, key=key)
reopened = AuditLog(P("a.jsonl"))
check("log reloads from disk with the same size and root", reopened.size == 10 and reopened.root() == log.root())

bad_calls = {
    "free-text reason (could hold personal data)": dict(type="ACCESS_DENIED", org_id=ORG, decision="deny", reason="Priya blood test denied"),
    "lower-case reason": dict(type="ACCESS_DENIED", org_id=ORG, decision="deny", reason="grant_revoked"),
    "email instead of an ID": dict(type="ACCESS_DENIED", org_id="priya@example.com", decision="deny", reason="X"),
    "unknown event type": dict(type="SOMETHING_ELSE", org_id=ORG, decision="deny", reason="X"),
    "unknown decision": dict(type="ACCESS_DENIED", org_id=ORG, decision="maybe", reason="X"),
}
for label, kw in bad_calls.items():
    check(f"schema rejects: {label}", raises(ValueError, lambda kw=kw: log.append(**kw)))
check("rejected events were not written", AuditLog(P("a.jsonl")).size == 10)

# ============ C. Tampering attacks on the file ============
orig = lines(P("a.jsonl"))

ls = list(orig); ev = json.loads(ls[3]); ev["decision"] = "allow"; ls[3] = json.dumps(ev, sort_keys=True)
write_lines(P("edit.jsonl"), ls)
check("ATTACK edit one event (deny -> allow): detected", raises(AuditCorruption, lambda: AuditLog(P("edit.jsonl"))))

write_lines(P("del.jsonl"), orig[:4] + orig[5:])
check("ATTACK delete an event in the middle: detected", raises(AuditCorruption, lambda: AuditLog(P("del.jsonl"))))

ls = list(orig); ls[2], ls[3] = ls[3], ls[2]
write_lines(P("swap.jsonl"), ls)
check("ATTACK swap two events: detected", raises(AuditCorruption, lambda: AuditLog(P("swap.jsonl"))))

# ============ D. What the file alone CANNOT catch, and what the checkpoint catches ============
user_cp = log.signed_checkpoint()              # a user (or auditor) saved this earlier
trunc = AuditLog  # readability
write_lines(P("trunc.jsonl"), orig[:7])
short = AuditLog(P("trunc.jsonl"))
check("LIMIT (expected): deleting the LAST events leaves a file that still verifies by itself", short.size == 7)
check("...but a user holding the old checkpoint (size 10) notices the log shrank",
      short.size < user_cp["size"] and raises(ValueError, lambda: short.consistency_proof(user_cp["size"])))

forged = fill(P("forged.jsonl"), 10, flip_at=3)       # operator rewrites event 3 AND recomputes every hash
check("LIMIT (expected): a fully re-built forged log passes its own file check", forged.size == 10 and forged.root() != log.root())
fcp = forged.checkpoint()
proof = forged.consistency_proof(6)
old6 = {"size": 6, "root": log.root(6)}            # the user saved the size-6 checkpoint of the HONEST log
check("...but the forged log cannot prove it extends the user's old checkpoint", not verify_consistency_proof(old6, fcp, proof))

honest_grown = fill(P("grown.jsonl"), 25)
cp6 = {"size": 6, "root": honest_grown.root(6)}
cp25 = honest_grown.checkpoint()
check("an honest log that only grew passes the consistency check from the old checkpoint",
      verify_consistency_proof(cp6, cp25, honest_grown.consistency_proof(6)))

# ============ E. Proof for a single user event ============
p7 = log.inclusion_proof(7)
cp_now = log.checkpoint()
check("a single event can be proven present using only ~log2(n) hashes and the trusted root",
      verify_inclusion_proof(p7, cp_now), f"{len(p7['path'])} hashes for a {log.size}-event log")
p3 = log.inclusion_proof(0, size=3)
cp3 = {"size": 3, "root": log.root(3)}
check("proof is accepted for the checkpoint it was made for", verify_inclusion_proof(p3, cp3))
check("a proof that CLAIMS a different tree size than the trusted checkpoint is rejected",
      not verify_inclusion_proof(dict(p3, size=4), cp3))
mine = log.event(7)
check("the user's own copy of the event matches the proven leaf", verify_event_matches_leaf(mine, p7["leafHash"]))
altered = dict(mine, decision="allow" if mine["decision"] == "deny" else "deny")
check("an altered copy of the event does NOT match", not verify_event_matches_leaf(altered, p7["leafHash"]))

# ============ F. Signed checkpoints ============
pub = key.public_key()
check("signed checkpoint verifies with the operator's public key", verify_signed_checkpoint(pub, user_cp))
check("checkpoint with a changed size fails", not verify_signed_checkpoint(pub, dict(user_cp, size=user_cp["size"] + 1)))
check("checkpoint verified against someone else's key fails",
      not verify_signed_checkpoint(Ed25519PrivateKey.generate().public_key(), user_cp))

# ============ G. Speed numbers for the report ============
big = AuditLog(P("big.jsonl"), signing_key=key)
t0 = time.perf_counter()
for i in range(2000):
    big.append(type="ACCESS_ALLOWED", org_id=ORG, grant_id=GRANT, asset_id=ASSET, decision="allow", reason="OK")
t1 = time.perf_counter()
root = big.root(); t2 = time.perf_counter()
pr = big.inclusion_proof(1234); t3 = time.perf_counter()
ok = verify_inclusion_proof(pr, big.checkpoint()); t4 = time.perf_counter()
print(f"INFO  2000 appends (each flushed to disk): {1000*(t1-t0):.0f} ms total = {1000*(t1-t0)/2000:.2f} ms each")
print(f"INFO  root {1000*(t2-t1):.1f} ms | inclusion proof {1000*(t3-t2):.1f} ms ({len(pr['path'])} hashes) | verify {1000*(t4-t3):.2f} ms")
check("proof for a 2000-event log verifies", ok)

tmp.cleanup()
print("\nALL TESTS PASSED" if failures == 0 else f"\n{failures} TEST(S) FAILED")
sys.exit(0 if failures == 0 else 1)
