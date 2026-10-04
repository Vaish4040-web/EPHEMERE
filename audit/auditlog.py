"""EPHEMERE audit log: an append-only, tamper-evident diary of every allow/deny decision.

How it protects history
  1. HASH CHAIN   each event stores the hash of the previous event (prevHash).
                  Editing or deleting an event in the middle breaks the chain.
  2. MERKLE ROOT  one short hash summarizes the whole log. Anyone who saved an earlier
                  checkpoint can ask for a CONSISTENCY PROOF to confirm the log was only
                  appended to, never rewritten.
  3. SIGNED CHECKPOINTS  the operator signs (size, root). If it ever shows two
                  inconsistent logs, the two signatures are proof of cheating.

No personal data can enter the log: the schema only accepts IDs, fixed event types,
fixed decisions, and short upper-case reason CODES (never free text).
"""
import base64
import json
import os
import re
import time
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import merkle

GENESIS_HASH = "0" * 64
EVENT_TYPES = {
    "REQUEST_CREATED", "ZK_VERIFIED", "ZK_FAILED", "GRANT_APPROVED", "ACCESS_ALLOWED",
    "ACCESS_DENIED", "REVOKED", "EXPIRED", "KEY_ROTATED", "ERASED",
}
DECISIONS = {"allow", "deny", "n/a"}
REASON_RE = re.compile(r"^[A-Z0-9_]{1,40}$")
UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
BODY_FIELDS = ("seq", "ts", "type", "grantId", "orgId", "assetId", "decision", "reason", "prevHash")
CHECKPOINT_PREFIX = b"EPHEMERE-CHECKPOINT-v1\n"


class AuditCorruption(Exception):
    """The log file does not verify (edited, reordered, or damaged)."""


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _check_schema(ev: dict):
    if set(ev) != set(BODY_FIELDS):
        raise ValueError(f"event fields must be exactly {BODY_FIELDS}")
    if ev["type"] not in EVENT_TYPES:
        raise ValueError("unknown event type")
    if ev["decision"] not in DECISIONS:
        raise ValueError("decision must be allow, deny or n/a")
    if not isinstance(ev["reason"], str) or not REASON_RE.match(ev["reason"]):
        raise ValueError("reason must be a short UPPER_CASE code, not free text")
    if not isinstance(ev["orgId"], str) or not UUID4_RE.match(ev["orgId"]):
        raise ValueError("orgId must be a UUIDv4")
    for k in ("grantId", "assetId"):
        if ev[k] is not None and not (isinstance(ev[k], str) and UUID4_RE.match(ev[k])):
            raise ValueError(f"{k} must be a UUIDv4 or null")
    if not isinstance(ev["seq"], int) or ev["seq"] < 0:
        raise ValueError("bad seq")
    if not (isinstance(ev["prevHash"], str) and re.fullmatch(r"[0-9a-f]{64}", ev["prevHash"])):
        raise ValueError("bad prevHash")


class AuditLog:
    def __init__(self, path, signing_key: Ed25519PrivateKey | None = None, clock=time.time):
        self.path = path
        self._key = signing_key
        self._clock = clock
        self._events = []     # list of dicts (as stored, including leafHash)
        self._leaves = []     # list of raw leaf hashes (bytes)
        if os.path.exists(path):
            self._load()

    # ------------------------------------------------------------- loading
    def _load(self):
        prev = GENESIS_HASH
        with open(self.path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                try:
                    ev = json.loads(line)
                    stored_leaf = ev.pop("leafHash")
                    _check_schema(ev)
                except Exception as e:
                    raise AuditCorruption(f"line {i}: unreadable or invalid event ({e})")
                if ev["seq"] != i:
                    raise AuditCorruption(f"line {i}: sequence number {ev['seq']} (event missing or reordered)")
                if ev["prevHash"] != prev:
                    raise AuditCorruption(f"line {i}: hash chain broken (an earlier event was changed or removed)")
                leaf = merkle.leaf_hash(_canonical(ev))
                if leaf.hex() != stored_leaf:
                    raise AuditCorruption(f"line {i}: event content does not match its hash (edited)")
                ev["leafHash"] = stored_leaf
                self._events.append(ev)
                self._leaves.append(leaf)
                prev = stored_leaf

    # ------------------------------------------------------------ appending
    def append(self, *, type, org_id, decision, reason, grant_id=None, asset_id=None) -> dict:
        prev = self._events[-1]["leafHash"] if self._events else GENESIS_HASH
        ts = datetime.fromtimestamp(self._clock(), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        body = {"seq": len(self._events), "ts": ts, "type": type, "grantId": grant_id, "orgId": org_id,
                "assetId": asset_id, "decision": decision, "reason": reason, "prevHash": prev}
        _check_schema(body)                       # rejects anything that could hold personal data
        leaf = merkle.leaf_hash(_canonical(body))
        ev = dict(body, leafHash=leaf.hex())
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._events.append(ev)
        self._leaves.append(leaf)
        return dict(ev)

    # ------------------------------------------------------------ read side
    @property
    def size(self) -> int:
        return len(self._events)

    def event(self, seq: int) -> dict:
        return dict(self._events[seq])

    def root(self, size: int | None = None) -> str:
        n = len(self._leaves) if size is None else size
        return merkle.root_of(self._leaves, 0, n).hex()

    def checkpoint(self) -> dict:
        return {"size": self.size, "root": self.root()}

    def signed_checkpoint(self) -> dict:
        if self._key is None:
            raise RuntimeError("no signing key configured")
        cp = self.checkpoint()
        cp["ts"] = datetime.fromtimestamp(self._clock(), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        msg = CHECKPOINT_PREFIX + _canonical({"size": cp["size"], "root": cp["root"], "ts": cp["ts"]})
        cp["sig"] = base64.b64encode(self._key.sign(msg)).decode()
        return cp

    def inclusion_proof(self, seq: int, size: int | None = None) -> dict:
        n = len(self._leaves) if size is None else size
        return {"seq": seq, "size": n, "leafHash": self._leaves[seq].hex(),
                "path": [h.hex() for h in merkle.inclusion_path(self._leaves[:n], seq)],
                "root": self.root(n)}

    def consistency_proof(self, old_size: int) -> dict:
        return {"oldSize": old_size, "newSize": self.size,
                "path": [h.hex() for h in merkle.consistency_path(self._leaves, old_size)]}


# ---------------------------------------------------- stand-alone verifiers
# These need NO access to the log: a user's browser or an auditor can run them.
def verify_inclusion_proof(proof: dict, trusted_cp: dict) -> bool:
    """`trusted_cp` is a checkpoint the verifier already trusts (size AND root come from it together).
    The size inside the proof is NOT trusted: it must equal the checkpoint's size."""
    if proof["size"] != trusted_cp["size"]:
        return False
    return merkle.verify_inclusion(bytes.fromhex(proof["leafHash"]), proof["seq"], trusted_cp["size"],
                                   [bytes.fromhex(h) for h in proof["path"]], bytes.fromhex(trusted_cp["root"]))


def verify_event_matches_leaf(event: dict, leaf_hash_hex: str) -> bool:
    """Check that a specific event (as the user remembers it) really hashes to the leaf in the proof."""
    body = {k: event[k] for k in BODY_FIELDS}
    return merkle.leaf_hash(_canonical(body)).hex() == leaf_hash_hex


def verify_consistency_proof(old_cp: dict, new_cp: dict, proof: dict) -> bool:
    return merkle.verify_consistency(old_cp["size"], new_cp["size"], bytes.fromhex(old_cp["root"]),
                                     bytes.fromhex(new_cp["root"]), [bytes.fromhex(h) for h in proof["path"]])


def verify_signed_checkpoint(public_key, cp: dict) -> bool:
    msg = CHECKPOINT_PREFIX + _canonical({"size": cp["size"], "root": cp["root"], "ts": cp["ts"]})
    try:
        public_key.verify(base64.b64decode(cp["sig"]), msg)
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False
