"""PROXY service. Later it holds kfrags and produces cfrags. It can NEVER read a file."""
from fastapi import Depends, FastAPI

from api.common.config import Settings
from api.common.errors import install_error_handlers
from api.common.security import internal_auth


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(title="EPHEMERE proxy")
    install_error_handlers(app)
    guard = Depends(internal_auth(settings.internal_secret))

    @app.get("/health")
    def health():
        return {"service": "proxy", "status": "ok"}

    @app.get("/internal/ping", dependencies=[guard])
    def ping():
        return {"service": "proxy", "ok": True}

    return app
