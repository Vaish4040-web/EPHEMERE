"""The proxy's memory: which permission pieces (kfrags) it holds, until when, and which ones were revoked.
It is kept in a small SQLite file so that a restart can never bring back a revoked permission.

The proxy can turn a capsule into cfrags, but it holds NO file key and NO file content, so it can never read a file."""
import base64
import hashlib
import json
import sqlite3
from pathlib import Path

from umbral_pre import Capsule, KeyFrag, PublicKey, reencrypt

from api.common.errors import ApiError

SCHEMA = """
CREATE TABLE IF NOT EXISTS policies (
  grant_id TEXT PRIMARY KEY, kfrags TEXT NOT NULL, digests TEXT NOT NULL, owner_pk TEXT NOT NULL,
  verifying_pk TEXT NOT NULL, delegate_pk TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS revoked_digests (digest TEXT PRIMARY KEY);
"""
b64d = base64.b64decode
b64e = lambda b: base64.b64encode(b).decode()


class PolicyStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    def _conn(self):
        return sqlite3.connect(self.path)

    @staticmethod
    def _keys(owner_pk: bytes, verifying_pk: bytes, delegate_pk: bytes):
        return (PublicKey.from_compressed_bytes(owner_pk), PublicKey.from_compressed_bytes(verifying_pk),
                PublicKey.from_compressed_bytes(delegate_pk))

    @staticmethod
    def _verified(kfrag_bytes: bytes, owner_pk, verifying_pk, delegate_pk):
        return KeyFrag.from_bytes(kfrag_bytes).verify(verifying_pk, owner_pk, delegate_pk)

    def store(self, grant_id: str, kfrags: list[bytes], expires_at: int, owner_pk: bytes, verifying_pk: bytes,
              delegate_pk: bytes, now: float) -> None:
        digests = [hashlib.sha256(k).hexdigest() for k in kfrags]
        with self._conn() as conn:
            row = conn.execute("SELECT revoked FROM policies WHERE grant_id = ?", (grant_id,)).fetchone()
            if row and row[0]:
                raise ApiError(403, "GRANT_REVOKED", "This permission was revoked and cannot be switched back on.")
            marks = ",".join("?" * len(digests))
            if conn.execute(f"SELECT 1 FROM revoked_digests WHERE digest IN ({marks})", digests).fetchone():
                raise ApiError(403, "KFRAG_REVOKED", "These permission pieces were revoked before.")
            if expires_at <= now:
                raise ApiError(422, "BAD_REQUEST", "This permission has already expired.")
            try:                                   # every piece must be signed by the owner, for exactly this delegate
                keys = self._keys(owner_pk, verifying_pk, delegate_pk)
                for k in kfrags:
                    self._verified(k, keys[0], keys[1], keys[2])
            except Exception:
                raise ApiError(422, "BAD_KFRAG", "These permission pieces are not valid for this file and service.")
            conn.execute(
                "INSERT OR REPLACE INTO policies (grant_id, kfrags, digests, owner_pk, verifying_pk, delegate_pk, expires_at, revoked)"
                " VALUES (?,?,?,?,?,?,?,0)",
                (grant_id, json.dumps([b64e(k) for k in kfrags]), json.dumps(digests), b64e(owner_pk),
                 b64e(verifying_pk), b64e(delegate_pk), int(expires_at)))

    def revoke(self, grant_id: str) -> None:
        with self._conn() as conn:
            row = conn.execute("SELECT digests FROM policies WHERE grant_id = ?", (grant_id,)).fetchone()
            if row:
                conn.executemany("INSERT OR IGNORE INTO revoked_digests (digest) VALUES (?)", [(d,) for d in json.loads(row[0])])
                conn.execute("UPDATE policies SET revoked = 1, kfrags = '[]' WHERE grant_id = ?", (grant_id,))
            else:                                  # unknown grant: still remember it, so it can never be registered later
                conn.execute("INSERT INTO policies (grant_id, kfrags, digests, owner_pk, verifying_pk, delegate_pk, expires_at, revoked)"
                             " VALUES (?, '[]', '[]', '', '', '', 0, 1)", (grant_id,))

    def reencrypt(self, grant_id: str, capsule: bytes, now: float) -> list[bytes]:
        with self._conn() as conn:
            row = conn.execute("SELECT kfrags, owner_pk, verifying_pk, delegate_pk, expires_at, revoked FROM policies WHERE grant_id = ?",
                               (grant_id,)).fetchone()
        if row is None:
            raise ApiError(404, "NOT_FOUND", "No such permission.")
        kfrags_json, owner_pk, verifying_pk, delegate_pk, expires_at, revoked = row
        if revoked:
            raise ApiError(403, "GRANT_REVOKED", "This permission was revoked.")
        if now >= expires_at:
            raise ApiError(403, "GRANT_EXPIRED", "This permission has ended.")
        try:
            cap = Capsule.from_bytes(capsule)
        except Exception:
            raise ApiError(422, "BAD_REQUEST", "The capsule is not valid.")
        owner, verifying, delegate = self._keys(b64d(owner_pk), b64d(verifying_pk), b64d(delegate_pk))
        return [bytes(reencrypt(cap, self._verified(b64d(k), owner, verifying, delegate))) for k in json.loads(kfrags_json)]
