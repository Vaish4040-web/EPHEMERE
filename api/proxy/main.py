"""PROXY service. It holds permission pieces (kfrags) and turns a capsule into cfrags while a permission is active.
It refuses after revoke or expiry. It can NEVER read a file: it holds no file key and no file content."""
import base64
import binascii
import time

from fastapi import Depends, FastAPI
from pydantic import BaseModel, ConfigDict, Field, field_validator

from api.common.config import Settings
from api.common.errors import install_error_handlers
from api.common.security import internal_auth
from api.proxy.store import PolicyStore, b64d, b64e


def _decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("not valid base64")


class PolicyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    grantId: str = Field(min_length=1, max_length=64)
    kfrags: list[str] = Field(min_length=1, max_length=16)
    expiresAt: int
    ownerPk: str
    verifyingPk: str
    delegatePk: str

    @field_validator("ownerPk", "verifyingPk", "delegatePk")
    @classmethod
    def _pk(cls, v):
        if len(_decode(v)) != 33:
            raise ValueError("a public key must be exactly 33 bytes")
        return v

    @field_validator("kfrags")
    @classmethod
    def _kfrags(cls, v):
        for item in v:
            if not 1 <= len(_decode(item)) <= 2048:
                raise ValueError("a kfrag must be 1 to 2048 bytes")
        return v


class ReencryptIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    grantId: str = Field(min_length=1, max_length=64)
    capsule: str

    @field_validator("capsule")
    @classmethod
    def _capsule(cls, v):
        if not 1 <= len(_decode(v)) <= 1024:
            raise ValueError("the capsule must be 1 to 1024 bytes")
        return v


def create_app(settings: Settings | None = None, clock=time.time, db_path=None) -> FastAPI:
    settings = settings or Settings.from_env()
    store = PolicyStore(db_path or settings.data_dir / "proxy.db")
    app = FastAPI(title="EPHEMERE proxy")
    install_error_handlers(app)
    guard = Depends(internal_auth(settings.internal_secret))

    @app.get("/health")
    def health():
        return {"service": "proxy", "status": "ok"}

    @app.get("/internal/ping", dependencies=[guard])
    def ping():
        return {"service": "proxy", "ok": True}

    @app.post("/internal/policies", status_code=201, dependencies=[guard])
    def store_policy(body: PolicyIn):
        store.store(body.grantId, [b64d(k) for k in body.kfrags], body.expiresAt, b64d(body.ownerPk),
                    b64d(body.verifyingPk), b64d(body.delegatePk), clock())
        return {"ok": True, "kfragCount": len(body.kfrags)}

    @app.post("/internal/reencrypt", dependencies=[guard])
    def reencrypt_for_grant(body: ReencryptIn):
        return {"cfrags": [b64e(c) for c in store.reencrypt(body.grantId, b64d(body.capsule), clock())]}

    @app.delete("/internal/policies/{grant_id}", dependencies=[guard])
    def revoke_policy(grant_id: str):
        store.revoke(grant_id)
        return {"revoked": True}

    return app
