"""Requests: a company asks for ONE field for a stated purpose; the person decides; the company gets only that field.
This is the policy engine. Every rule is checked here, and the proxy enforces expiry and revocation again on its own."""
import base64
import binascii
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, field_validator

from api.common.errors import ApiError
from api.common.policy import FIELDS, MAX_DURATION_SEC, MIN_DURATION_SEC, PURPOSES, purpose_allows
from api.gateway.auth import ACCOUNTS, ACCOUNTS_BY_ID, AuthKit
from api.gateway.internal import InternalClient
from api.gateway.ipfs import IpfsClient

UUID4 = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
iso = lambda t: datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=40)
    field: str
    purpose: str
    durationSec: int = Field(ge=MIN_DURATION_SEC, le=MAX_DURATION_SEC)

    @field_validator("field")
    @classmethod
    def _field(cls, v):
        if v not in FIELDS:
            raise ValueError("unknown field")
        return v

    @field_validator("purpose")
    @classmethod
    def _purpose(cls, v):
        if v not in PURPOSES:
            raise ValueError("unknown purpose")
        return v


class ApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assetId: str = Field(pattern=UUID4)
    kfrags: list[str] = Field(min_length=1, max_length=16)

    @field_validator("kfrags")
    @classmethod
    def _kfrags(cls, v):
        for item in v:
            try:
                raw = base64.b64decode(item, validate=True)
            except (binascii.Error, ValueError):
                raise ValueError("not valid base64")
            if not 1 <= len(raw) <= 2048:
                raise ValueError("a kfrag must be 1 to 2048 bytes")
        return v


def make_requests_router(db_path: Path, ipfs: IpfsClient, internal: InternalClient, auth: AuthKit, clock) -> APIRouter:
    router = APIRouter()

    def connect():
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    BASE = ("SELECT r.*, g.id AS grant_id, g.status AS grant_status, g.expires_epoch AS expires_epoch "
            "FROM requests r LEFT JOIN grants g ON g.request_id = r.id ")

    def status_of(row) -> str:
        """pending / approved / denied, plus 'revoked' and 'expired' which come from the grant and the clock."""
        if row["status"] != "approved":
            return row["status"]
        if row["grant_status"] == "revoked":
            return "revoked"
        if row["expires_epoch"] is not None and clock() >= row["expires_epoch"]:
            return "expired"
        return "approved"

    def show(row, *, for_org: bool) -> dict:
        out = {"requestId": row["id"], "field": row["field"], "purpose": row["purpose"],
               "durationSec": row["duration_sec"], "status": status_of(row), "createdAt": row["created_at"],
               "expiresAt": row["expires_epoch"], "grantId": row["grant_id"], "assetId": row["asset_id"]}
        if for_org:
            out["subject"] = ACCOUNTS_BY_ID[row["subject_id"]]["name"]
            out.pop("assetId")                         # a company never learns which file was used
            out.pop("grantId")
        else:
            out["org"] = ACCOUNTS_BY_ID[row["org_id"]]["name"]
        return out

    def find(conn, request_id: str, column: str, who: str):
        row = conn.execute(BASE + f"WHERE r.id = ? AND r.{column} = ?", (request_id, who)).fetchone()
        if row is None:                                # same answer whether it does not exist or belongs to someone else
            raise ApiError(404, "NOT_FOUND", "Request not found.")
        return row

    # --------------------------------------------------------------- public rules
    @router.get("/api/policy")
    def policy():
        return {"purposes": [{"code": c, "label": p["label"], "fields": p["fields"]} for c, p in PURPOSES.items()],
                "minDurationSec": MIN_DURATION_SEC, "maxDurationSec": MAX_DURATION_SEC}

    @router.get("/api/access-key")
    async def access_key(user: dict = Depends(auth.require_user)):
        return {"publicKey": await internal.access_public_key()}

    # --------------------------------------------------------------- the company
    @router.post("/api/org/requests", status_code=201)
    def ask(body: RequestIn, org: dict = Depends(auth.require_org)):
        person = ACCOUNTS.get(body.subject)
        if person is None or person["role"] != "user":
            raise ApiError(404, "NOT_FOUND", "No such person.")
        if not purpose_allows(body.purpose, body.field):
            raise ApiError(422, "PURPOSE_NOT_ALLOWED", "That purpose does not allow asking for that field.")
        request_id = str(uuid.uuid4())
        with connect() as conn:
            conn.execute("INSERT INTO requests (id, org_id, subject_id, field, purpose, duration_sec, status, created_at)"
                         " VALUES (?,?,?,?,?,?, 'pending', ?)",
                         (request_id, org["id"], person["id"], body.field, body.purpose, body.durationSec, iso(clock())))
        return {"requestId": request_id, "status": "pending"}

    @router.get("/api/org/requests")
    def org_requests(org: dict = Depends(auth.require_org)):
        with connect() as conn:
            rows = conn.execute(BASE + "WHERE r.org_id = ? ORDER BY r.created_at DESC, r.rowid DESC", (org["id"],)).fetchall()
        return {"requests": [show(r, for_org=True) for r in rows]}

    @router.post("/api/org/requests/{request_id}/access")
    async def access(request_id: str, org: dict = Depends(auth.require_org)):
        with connect() as conn:
            row = find(conn, request_id, "org_id", org["id"])
            asset = conn.execute("SELECT * FROM assets WHERE id = ?", (row["asset_id"],)).fetchone() if row["asset_id"] else None
        if row["status"] != "approved" or asset is None:
            raise ApiError(403, "REQUEST_NOT_APPROVED", "The person has not approved this request.")
        if row["grant_status"] == "revoked":
            raise ApiError(403, "GRANT_REVOKED", "The person has withdrawn this permission.")
        if clock() >= row["expires_epoch"]:
            raise ApiError(403, "GRANT_EXPIRED", "This permission has ended.")
        cfrags = await internal.proxy_reencrypt(row["grant_id"], asset["capsule"])      # the proxy checks revoke and expiry again
        ciphertext = await ipfs.cat(asset["cid"])
        result = await internal.access_open({
            "assetId": asset["id"], "field": row["field"], "capsule": asset["capsule"], "wrappedDek": asset["wrapped_dek"],
            "iv": asset["iv"], "ownerPk": asset["owner_pk"], "verifyingPk": asset["verifying_pk"],
            "ciphertext": base64.b64encode(ciphertext).decode(), "cfrags": cfrags})
        return {"requestId": request_id, "field": result["field"], "value": result["value"]}

    # --------------------------------------------------------------- the person
    @router.get("/api/user/requests")
    def user_requests(user: dict = Depends(auth.require_user)):
        with connect() as conn:
            rows = conn.execute(BASE + "WHERE r.subject_id = ? ORDER BY r.created_at DESC, r.rowid DESC", (user["id"],)).fetchall()
        return {"requests": [show(r, for_org=False) for r in rows]}

    @router.post("/api/user/requests/{request_id}/approve")
    async def approve(request_id: str, body: ApproveIn, user: dict = Depends(auth.require_user)):
        with connect() as conn:
            row = find(conn, request_id, "subject_id", user["id"])
            if row["status"] != "pending":
                raise ApiError(409, "CONFLICT", "This request has already been decided.")
            asset = conn.execute("SELECT * FROM assets WHERE id = ? AND owner_id = ?", (body.assetId, user["id"])).fetchone()
            if asset is None:
                raise ApiError(404, "NOT_FOUND", "File not found.")
        grant_id = str(uuid.uuid4())
        expires = int(clock()) + row["duration_sec"]
        delegate_pk = await internal.access_public_key()
        await internal.proxy_store(grant_id, body.kfrags, expires, asset["owner_pk"], asset["verifying_pk"], delegate_pk)
        try:
            with connect() as conn:
                changed = conn.execute("UPDATE requests SET status = 'approved', asset_id = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
                                       (asset["id"], iso(clock()), request_id)).rowcount
                if changed != 1:
                    raise sqlite3.IntegrityError("already decided")
                conn.execute("INSERT INTO grants (id, request_id, asset_id, status, expires_epoch, created_at) VALUES (?,?,?, 'active', ?, ?)",
                             (grant_id, request_id, asset["id"], expires, iso(clock())))
        except sqlite3.Error:
            try:
                await internal.proxy_revoke(grant_id)      # do not leave a live permission nobody can see
            except ApiError:
                pass
            raise ApiError(409, "CONFLICT", "This request has already been decided.")
        return {"requestId": request_id, "status": "approved", "grantId": grant_id, "expiresAt": expires}

    @router.post("/api/user/requests/{request_id}/deny")
    def deny(request_id: str, user: dict = Depends(auth.require_user)):
        with connect() as conn:
            find(conn, request_id, "subject_id", user["id"])
            changed = conn.execute("UPDATE requests SET status = 'denied', decided_at = ? WHERE id = ? AND status = 'pending'",
                                   (iso(clock()), request_id)).rowcount
        if changed != 1:
            raise ApiError(409, "CONFLICT", "This request has already been decided.")
        return {"requestId": request_id, "status": "denied"}

    return router
