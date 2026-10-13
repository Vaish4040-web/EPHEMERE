"""ACCESS service (the 'delegate'). It recovers the file key and decrypts a file IN MEMORY, takes out the ONE field
that was asked for, and returns only that. It never returns the file, never logs it and never writes it to disk.

It owns an Umbral key pair that is created once and kept in the data folder (never committed)."""
import base64
import binascii
import json
import os
from typing import Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI
from pydantic import BaseModel, ConfigDict, Field, field_validator
from umbral_pre import Capsule, CapsuleFrag, PublicKey, SecretKey, decrypt_reencrypted

from api.common.config import Settings
from api.common.errors import ApiError, install_error_handlers
from api.common.policy import MAX_VALUE_CHARS
from api.common.security import internal_auth

UUID4 = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
MAX_CIPHERTEXT = 5_100_000


def load_or_create_key(path) -> SecretKey:
    if path.exists():
        return SecretKey.from_be_bytes(base64.b64decode(json.loads(path.read_text())["secretKey"]))
    path.parent.mkdir(parents=True, exist_ok=True)
    sk = SecretKey.random()
    path.write_text(json.dumps({"secretKey": base64.b64encode(sk.to_be_bytes()).decode()}))
    try:
        os.chmod(path, 0o600)       # owner-only on Linux/Mac (Windows ignores this)
    except OSError:
        pass
    return sk


def _decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("not valid base64")


class OpenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assetId: str = Field(pattern=UUID4)
    field: Literal["address", "blood_group", "name", "phone"]       # only these can ever be asked for
    capsule: str
    wrappedDek: str
    iv: str
    ownerPk: str
    verifyingPk: str
    ciphertext: str
    cfrags: list[str] = Field(min_length=1, max_length=16)

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
        if not 1 <= len(_decode(v)) <= MAX_CIPHERTEXT:
            raise ValueError("the file size is not allowed")
        return v

    @field_validator("cfrags")
    @classmethod
    def _cfrags(cls, v):
        for item in v:
            if not 1 <= len(_decode(item)) <= 2048:
                raise ValueError("a cfrag must be 1 to 2048 bytes")
        return v


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    secret_key = load_or_create_key(settings.data_dir / "access_key.json")
    my_public_key = secret_key.public_key()
    public_key_b64 = base64.b64encode(my_public_key.to_compressed_bytes()).decode()

    app = FastAPI(title="EPHEMERE access service")
    install_error_handlers(app)
    guard = Depends(internal_auth(settings.internal_secret))

    @app.get("/health")
    def health():
        return {"service": "access", "status": "ok"}

    @app.get("/internal/ping", dependencies=[guard])
    def ping():
        return {"service": "access", "ok": True, "keyReady": True}

    @app.get("/internal/public-key", dependencies=[guard])
    def public_key():
        return {"publicKey": public_key_b64}

    @app.post("/internal/open", dependencies=[guard])
    def open_field(body: OpenIn):
        """The only place where a file is ever readable, and only for the length of this call.
        Nothing here is logged, and nothing is stored."""
        try:
            capsule = Capsule.from_bytes(base64.b64decode(body.capsule))
            owner_pk = PublicKey.from_compressed_bytes(base64.b64decode(body.ownerPk))
            verifying_pk = PublicKey.from_compressed_bytes(base64.b64decode(body.verifyingPk))
        except Exception:
            raise ApiError(422, "BAD_REQUEST", "The request is not valid.")
        try:                       # every cfrag must belong to THIS file and to THIS service
            verified = [CapsuleFrag.from_bytes(base64.b64decode(c)).verify(capsule, verifying_pk, owner_pk, my_public_key)
                        for c in body.cfrags]
        except Exception:
            raise ApiError(403, "CFRAG_INVALID", "The re-encryption pieces are not valid for this file and service.")
        try:
            dek = decrypt_reencrypted(secret_key, owner_pk, capsule, verified, base64.b64decode(body.wrappedDek))
        except Exception:
            raise ApiError(403, "KEY_RECOVERY_FAILED", "The file key could not be recovered.")
        try:
            plain = AESGCM(bytes(dek)).decrypt(base64.b64decode(body.iv), base64.b64decode(body.ciphertext), body.assetId.encode())
        except InvalidTag:
            raise ApiError(422, "DECRYPT_FAILED", "The file could not be decrypted.")
        try:
            document = json.loads(plain)
        except ValueError:
            document = None
        del plain, dek             # drop our references right away (Python cannot promise to wipe memory)
        if not isinstance(document, dict):
            raise ApiError(422, "BAD_FILE", "The file is not in a readable format.")
        if body.field not in document:
            raise ApiError(404, "FIELD_NOT_FOUND", "The file does not contain that field.")
        value = document[body.field]
        del document
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            raise ApiError(422, "FIELD_TYPE_NOT_ALLOWED", "Only text or a number can be returned.")
        if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
            raise ApiError(422, "FIELD_TOO_LARGE", "That field is too large to return.")
        return {"field": body.field, "value": value}

    return app
