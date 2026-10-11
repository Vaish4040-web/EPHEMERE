"""ACCESS service (the 'delegate'). Later it recovers the file key and decrypts IN MEMORY only.
It owns an Umbral key pair that is created once and kept in the data folder (never committed)."""
import base64
import json
import os

from fastapi import Depends, FastAPI
from umbral_pre import SecretKey

from api.common.config import Settings
from api.common.errors import install_error_handlers
from api.common.security import internal_auth


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


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    secret_key = load_or_create_key(settings.data_dir / "access_key.json")
    public_key_b64 = base64.b64encode(secret_key.public_key().to_compressed_bytes()).decode()

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

    return app
