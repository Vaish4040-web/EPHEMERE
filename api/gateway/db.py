"""SQLite database. M1 schema is a first sketch; it will change as M2 to M4 need more columns."""
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, cid TEXT NOT NULL, iv TEXT NOT NULL,
  capsule TEXT NOT NULL, wrapped_dek TEXT NOT NULL, owner_pk TEXT NOT NULL,
  verifying_pk TEXT NOT NULL, created_at TEXT NOT NULL);
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
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)


def table_names(path: Path) -> list[str]:
    with sqlite3.connect(path) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
    return sorted(r[0] for r in rows)
