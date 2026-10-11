"""Encrypted files. The gateway only ever sees CIPHERTEXT plus the pieces the owner needs to open it later.
The file bytes live in IPFS; the database keeps metadata only."""
import base64
import binascii
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from api.common.errors import ApiError
from api.gateway.ipfs import IpfsClient

MAX_BYTES = 5_000_000
UUID4 = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"


def _decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("not valid base64")


class AssetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assetId: str = Field(pattern=UUID4)
    label: str = Field(pattern=r"^[A-Za-z0-9 ._()-]{1,40}$")   # shown in plain text: never put personal details here
    iv: str
    capsule: str
    wrappedDek: str
    ownerPk: str
    verifyingPk: str
    ciphertext: str

    @field_validator("iv")
    @classmethod
    def _iv(cls, v):
        if len(_decode(v)) != 12:
            raise ValueError("the IV must be exactly 12 bytes")
        return v

    @field_validator("ownerPk", "verifyingPk")
    @classmethod
    def _pk(cls, v):
        if len(_decode(v)) != 33:
            raise ValueError("a public key must be exactly 33 bytes")
        return v

    @field_validator("capsule", "wrappedDek")
    @classmethod
    def _small(cls, v):
        if not 1 <= len(_decode(v)) <= 1024:
            raise ValueError("must be 1 to 1024 bytes")
        return v

    @field_validator("ciphertext")
    @classmethod
    def _cipher(cls, v):
        if len(_decode(v)) < 1:
            raise ValueError("the file is empty")
        return v


def make_assets_router(db_path: Path, ipfs: IpfsClient, require_user) -> APIRouter:
    router = APIRouter()

    def connect():
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def own_asset(conn, asset_id: str, owner_id: str):
        row = conn.execute("SELECT * FROM assets WHERE id = ? AND owner_id = ?", (asset_id, owner_id)).fetchone()
        if row is None:        # same answer whether it does not exist or belongs to someone else
            raise ApiError(404, "NOT_FOUND", "File not found.")
        return row

    @router.post("/api/assets", status_code=201)
    async def upload(body: AssetIn, user: dict = Depends(require_user)):
        data = base64.b64decode(body.ciphertext)
        if len(data) > MAX_BYTES:
            raise ApiError(413, "FILE_TOO_LARGE", "Files can be at most 5 MB.")
        with connect() as conn:
            if conn.execute("SELECT 1 FROM assets WHERE id = ?", (body.assetId,)).fetchone():
                raise ApiError(409, "CONFLICT", "A file with this ID already exists.")
        cid = await ipfs.add(data)          # if storage fails, nothing is recorded
        try:
            with connect() as conn:
                conn.execute(
                    "INSERT INTO assets (id, owner_id, label, cid, size_bytes, iv, capsule, wrapped_dek, owner_pk, verifying_pk, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (body.assetId, user["id"], body.label, cid, len(data), body.iv, body.capsule, body.wrappedDek,
                     body.ownerPk, body.verifyingPk, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
                )
        except sqlite3.IntegrityError:
            raise ApiError(409, "CONFLICT", "A file with this ID already exists.")
        return {"assetId": body.assetId, "cid": cid, "sizeBytes": len(data)}

    @router.get("/api/assets")
    def list_assets(user: dict = Depends(require_user)):
        with connect() as conn:
            rows = conn.execute(
                "SELECT id, label, cid, size_bytes, created_at FROM assets WHERE owner_id = ? ORDER BY created_at DESC, rowid DESC",
                (user["id"],),
            ).fetchall()
        return {"assets": [{"assetId": r["id"], "label": r["label"], "cid": r["cid"],
                            "sizeBytes": r["size_bytes"], "createdAt": r["created_at"]} for r in rows]}

    @router.get("/api/assets/{asset_id}")
    def get_asset(asset_id: str, user: dict = Depends(require_user)):
        with connect() as conn:
            r = own_asset(conn, asset_id, user["id"])
        return {"assetId": r["id"], "label": r["label"], "cid": r["cid"], "sizeBytes": r["size_bytes"],
                "createdAt": r["created_at"], "iv": r["iv"], "capsule": r["capsule"], "wrappedDek": r["wrapped_dek"],
                "ownerPk": r["owner_pk"], "verifyingPk": r["verifying_pk"]}

    @router.get("/api/assets/{asset_id}/ciphertext")
    async def get_ciphertext(asset_id: str, user: dict = Depends(require_user)):
        with connect() as conn:
            r = own_asset(conn, asset_id, user["id"])
        return Response(content=await ipfs.cat(r["cid"]), media_type="application/octet-stream")

    return router
