"""SQLite database.

SCHEMA_VERSION 2 (M2). While the project is still in the building phase, an older sketch of the tables
is simply replaced (nothing valuable is stored yet). From the first real data onwards, changes must be
proper migrations that keep the data.
"""
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, label TEXT NOT NULL, cid TEXT NOT NULL,
  size_bytes INTEGER NOT NULL, iv TEXT NOT NULL, capsule TEXT NOT NULL, wrapped_dek TEXT NOT NULL,
  owner_pk TEXT NOT NULL, verifying_pk TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS assets_owner ON assets (owner_id);
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL, asset_id TEXT NOT NULL, field TEXT,
  needs_age_proof INTEGER NOT NULL DEFAULT 0, purpose TEXT NOT NULL, duration_sec INTEGER NOT NULL,
  status TEXT NOT NULL, nonce TEXT, cutoff_day INTEGER, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, request_id TEXT NOT NULL, status TEXT NOT NULL,
  expires_at TEXT NOT NULL, created_at TEXT NOT NULL);
"""


def init_db(path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version < SCHEMA_VERSION:
            conn.executescript("DROP TABLE IF EXISTS assets; DROP TABLE IF EXISTS requests; DROP TABLE IF EXISTS grants;")
        conn.executescript(SCHEMA)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()
    finally:
        conn.close()


def table_names(path: Path) -> list[str]:
    with sqlite3.connect(path) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
    return sorted(r[0] for r in rows)
