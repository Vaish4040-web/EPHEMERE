"""SQLite database.

SCHEMA_VERSION 3 (M3). Uploaded files (assets) are never thrown away by an upgrade. Tables that were
never used before a milestone may be replaced; anything holding real data needs a proper migration.
"""
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, label TEXT NOT NULL, cid TEXT NOT NULL,
  size_bytes INTEGER NOT NULL, iv TEXT NOT NULL, capsule TEXT NOT NULL, wrapped_dek TEXT NOT NULL,
  owner_pk TEXT NOT NULL, verifying_pk TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS assets_owner ON assets (owner_id);
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL, subject_id TEXT NOT NULL, asset_id TEXT,
  field TEXT NOT NULL, purpose TEXT NOT NULL, duration_sec INTEGER NOT NULL,
  needs_age_proof INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
  nonce TEXT, cutoff_day INTEGER, created_at TEXT NOT NULL, decided_at TEXT);
CREATE INDEX IF NOT EXISTS requests_org ON requests (org_id);
CREATE INDEX IF NOT EXISTS requests_subject ON requests (subject_id);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, asset_id TEXT NOT NULL, status TEXT NOT NULL,
  expires_epoch INTEGER NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT);
"""


def init_db(path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version < 2:        # the M1 sketch: nothing worth keeping
            conn.executescript("DROP TABLE IF EXISTS assets; DROP TABLE IF EXISTS requests; DROP TABLE IF EXISTS grants;")
        elif version < 3:      # M2 -> M3: uploaded files (assets) are KEPT; requests and grants were never used before M3
            conn.executescript("DROP TABLE IF EXISTS requests; DROP TABLE IF EXISTS grants;")
        conn.executescript(SCHEMA)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()
    finally:
        conn.close()


def table_names(path: Path) -> list[str]:
    with sqlite3.connect(path) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
    return sorted(r[0] for r in rows)
