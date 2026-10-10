"""EPHEMERE audit: Merkle tree helpers (same construction as Certificate Transparency, RFC 6962/9162).

Why a Merkle tree?
  * ROOT          : one short hash that summarizes the whole log.
  * INCLUSION     : prove "my event is in the log" using ~log2(n) hashes, without seeing other events.
  * CONSISTENCY   : prove "the log with root R_old is a prefix of the log with root R_new",
                    i.e. history was only appended to, never rewritten.

Only Python's standard `hashlib` (SHA-256) is used. No custom crypto.
Leaves and inner nodes use different prefixes (0x00 / 0x01) so one can never be mistaken for the other.
"""
import hashlib

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root_of(leaves, lo=0, hi=None) -> bytes:
    """Merkle root of leaves[lo:hi]. `leaves` is a list of leaf hashes (bytes)."""
    if hi is None:
        hi = len(leaves)
    n = hi - lo
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaves[lo]
    k = _split(n)
    return node_hash(root_of(leaves, lo, lo + k), root_of(leaves, lo + k, hi))


# ---------------------------------------------------------------- inclusion
def inclusion_path(leaves, index, lo=0, hi=None):
    """Hashes needed to prove that leaves[index] is in the tree."""
    if hi is None:
        hi = len(leaves)
    n = hi - lo
    if not (0 <= index < n):
        raise ValueError("index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_path(leaves, index, lo, lo + k) + [root_of(leaves, lo + k, hi)]
    return inclusion_path(leaves, index - k, lo + k, hi) + [root_of(leaves, lo, lo + k)]


def verify_inclusion(leaf: bytes, index: int, size: int, path, root: bytes) -> bool:
    """Check an inclusion proof (RFC 9162, section 2.1.3.2)."""
    if not (0 <= index < size):
        return False
    fn, sn = index, size - 1
    r = leaf
    for p in path:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = node_hash(p, r)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# -------------------------------------------------------------- consistency
def _subproof(leaves, m, lo, hi, complete):
    n = hi - lo
    if m == n:
        return [] if complete else [root_of(leaves, lo, hi)]
    k = _split(n)
    if m <= k:
        return _subproof(leaves, m, lo, lo + k, complete) + [root_of(leaves, lo + k, hi)]
    return _subproof(leaves, m - k, lo + k, hi, False) + [root_of(leaves, lo, lo + k)]


def consistency_path(leaves, old_size, new_size=None):
    """Hashes proving the first `old_size` leaves are an unchanged prefix of the first `new_size` leaves."""
    n = len(leaves) if new_size is None else new_size
    if not (0 <= old_size <= n <= len(leaves)):
        raise ValueError("bad sizes")
    if old_size == 0 or old_size == n:
        return []
    return _subproof(leaves, old_size, 0, n, True)


def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof) -> bool:
    """Check a consistency proof (RFC 9162, section 2.1.4.2)."""
    if old_size > new_size or old_size < 0:
        return False
    if old_size == new_size:
        return list(proof) == [] and old_root == new_root
    if old_size == 0:
        return list(proof) == [] and old_root == EMPTY_ROOT
    if not proof:
        return False
    path = list(proof)
    if old_size & (old_size - 1) == 0:       # old_size is a power of two
        path = [old_root] + path
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0
