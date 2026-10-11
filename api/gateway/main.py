"""GATEWAY: the only service the browser pages talk to.
M1: health + an honest status report. Later: requests, approvals, access, revoke, audit."""
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from api.common.config import Settings
from api.common.errors import install_error_handlers
from api.gateway.assets import make_assets_router
from api.gateway.auth import make_auth
from api.gateway.db import init_db, table_names
from api.gateway.ipfs import IpfsClient


def create_app(settings: Settings | None = None, client: httpx.AsyncClient | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    db_path = settings.data_dir / "ephemere.db"
    init_db(db_path)
    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=3.0)
    secret_header = {"X-Internal-Secret": settings.internal_secret}

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        if owns_client:
            await http.aclose()

    app = FastAPI(title="EPHEMERE gateway", lifespan=lifespan)
    install_error_handlers(app)

    auth = make_auth(settings.demo_login)
    app.include_router(auth.router)
    app.include_router(make_assets_router(db_path, IpfsClient(http, settings.ipfs_url), auth.require_user))

    async def check_internal(name: str, url: str) -> dict:
        try:
            r = await http.get(f"{url}/internal/ping", headers=secret_header)
            if r.status_code == 200 and r.json().get("ok"):
                detail = "running" + (", key ready" if r.json().get("keyReady") else "")
                return {"ok": True, "detail": detail}
            return {"ok": False, "detail": f"answered with status {r.status_code}"}
        except Exception:
            return {"ok": False, "detail": f"{name} is not reachable"}

    async def check_ipfs() -> dict:
        try:
            r = await http.post(f"{settings.ipfs_url}/api/v0/version")
            return {"ok": True, "detail": f"Kubo {r.json()['Version']}"}
        except Exception:
            return {"ok": False, "detail": "IPFS is not reachable"}

    def check_database() -> dict:
        try:
            tables = table_names(db_path)
            return {"ok": True, "detail": f"{len(tables)} tables"}
        except Exception:
            return {"ok": False, "detail": "database cannot be opened"}

    @app.get("/health")
    def health():
        return {"service": "gateway", "status": "ok"}

    @app.get("/api/status")
    async def status():
        parts = {
            "gateway": {"ok": True, "detail": "running"},
            "proxy": await check_internal("proxy", settings.proxy_url),
            "access": await check_internal("access service", settings.access_url),
            "ipfs": await check_ipfs(),
            "database": check_database(),
        }
        return {**parts, "allOk": all(p["ok"] for p in parts.values())}

    return app
