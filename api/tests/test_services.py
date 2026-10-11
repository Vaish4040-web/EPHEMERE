"""M1 tests (written BEFORE the code): the three services start, protect their internal doors,
and the gateway reports honestly whether everything is up.

Run from the repo root:   python -m pytest -q
"""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from api.access.main import create_app as create_access
from api.common.config import Settings, load_env
from api.gateway.db import table_names
from api.gateway.main import create_app as create_gateway
from api.proxy.main import create_app as create_proxy

SECRET = "test-secret-0123456789abcdef"
GOOD = {"X-Internal-Secret": SECRET}


@pytest.fixture
def settings(tmp_path):
    return Settings(internal_secret=SECRET, data_dir=tmp_path)


# ------------------------------------------------------------------ settings
def test_settings_refuse_to_start_without_a_secret():
    with pytest.raises(ValueError, match="INTERNAL_SECRET"):
        Settings.from_env(environ={}, read_env_file=False)


def test_settings_refuse_a_short_secret():
    with pytest.raises(ValueError, match="INTERNAL_SECRET"):
        Settings.from_env(environ={"INTERNAL_SECRET": "short"}, read_env_file=False)


def test_settings_refuse_the_example_placeholder_secret():
    with pytest.raises(ValueError, match="INTERNAL_SECRET"):
        Settings.from_env(environ={"INTERNAL_SECRET": "change-me-to-a-long-random-string"}, read_env_file=False)


def test_env_file_is_read_but_never_overrides_real_environment(tmp_path):
    f = tmp_path / ".env"
    f.write_text('# comment\nA=1\nB="two"\n\nINTERNAL_SECRET=from-file-0123456789\n', encoding="utf-8")
    env = {"A": "already-set"}
    load_env(f, environ=env)
    assert env["A"] == "already-set" and env["B"] == "two" and env["INTERNAL_SECRET"] == "from-file-0123456789"


# --------------------------------------------------------------------- proxy
def test_proxy_health_is_open_and_says_nothing_sensitive(settings):
    r = TestClient(create_proxy(settings)).get("/health")
    assert r.status_code == 200 and r.json() == {"service": "proxy", "status": "ok"}


def test_proxy_internal_door_needs_the_secret(settings):
    c = TestClient(create_proxy(settings))
    missing = c.get("/internal/ping")
    assert missing.status_code == 401 and missing.json()["error"]["code"] == "UNAUTHENTICATED"
    wrong = c.get("/internal/ping", headers={"X-Internal-Secret": "x" * 30})
    assert wrong.status_code == 403 and wrong.json()["error"]["code"] == "FORBIDDEN"
    ok = c.get("/internal/ping", headers=GOOD)
    assert ok.status_code == 200 and ok.json() == {"service": "proxy", "ok": True}


# -------------------------------------------------------------------- access
def test_access_internal_door_needs_the_secret(settings):
    c = TestClient(create_access(settings))
    assert c.get("/health").json() == {"service": "access", "status": "ok"}
    assert c.get("/internal/ping").status_code == 401
    assert c.get("/internal/ping", headers={"X-Internal-Secret": "y" * 30}).status_code == 403
    ok = c.get("/internal/ping", headers=GOOD)
    assert ok.status_code == 200 and ok.json() == {"service": "access", "ok": True, "keyReady": True}


def test_access_key_is_created_once_and_reused_after_restart(settings):
    first = TestClient(create_access(settings)).get("/internal/public-key", headers=GOOD).json()["publicKey"]
    assert (settings.data_dir / "access_key.json").exists()
    second = TestClient(create_access(settings)).get("/internal/public-key", headers=GOOD).json()["publicKey"]
    assert first == second


def test_access_never_reveals_its_secret_key(settings):
    c = TestClient(create_access(settings))
    secret_b64 = json.loads((settings.data_dir / "access_key.json").read_text())["secretKey"]
    for path in ("/health", "/internal/ping", "/internal/public-key"):
        assert secret_b64 not in c.get(path, headers=GOOD).text


def test_public_key_door_is_protected_too(settings):
    assert TestClient(create_access(settings)).get("/internal/public-key").status_code == 401


# ------------------------------------------------------------------- gateway
def make_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def all_up(seen=None):
    def handler(request: httpx.Request):
        if seen is not None:
            seen.append((request.url.port, request.headers.get("x-internal-secret")))
        if request.url.path == "/internal/ping" and request.url.port == 8001:
            return httpx.Response(200, json={"service": "proxy", "ok": True})
        if request.url.path == "/internal/ping" and request.url.port == 8002:
            return httpx.Response(200, json={"service": "access", "ok": True, "keyReady": True})
        if request.url.path == "/api/v0/version":
            return httpx.Response(200, json={"Version": "0.43.1"})
        return httpx.Response(404)
    return handler


def test_gateway_health(settings):
    r = TestClient(create_gateway(settings, make_client(all_up()))).get("/health")
    assert r.json() == {"service": "gateway", "status": "ok"}


def test_gateway_status_when_everything_is_up(settings):
    seen = []
    r = TestClient(create_gateway(settings, make_client(all_up(seen)))).get("/api/status")
    body = r.json()
    assert r.status_code == 200 and body["allOk"] is True
    assert body["proxy"]["ok"] and body["access"]["ok"] and body["ipfs"]["ok"] and body["database"]["ok"]
    assert "0.43.1" in body["ipfs"]["detail"] and "3 tables" in body["database"]["detail"]
    # the gateway proves who it is to the internal services...
    assert (8001, SECRET) in seen and (8002, SECRET) in seen
    # ...but never leaks the secret to the browser
    assert SECRET not in r.text


def test_gateway_status_reports_a_service_that_is_down(settings):
    def handler(request):
        if request.url.port == 8001:
            raise httpx.ConnectError("refused")
        return all_up()(request)
    r = TestClient(create_gateway(settings, make_client(handler))).get("/api/status")
    body = r.json()
    assert r.status_code == 200 and body["allOk"] is False
    assert body["proxy"]["ok"] is False and body["access"]["ok"] is True


def test_gateway_status_catches_a_wrong_secret_on_an_internal_service(settings):
    def handler(request):
        if request.url.port == 8002:
            return httpx.Response(403, json={"error": {"code": "FORBIDDEN", "message": "Wrong internal secret"}})
        return all_up()(request)
    body = TestClient(create_gateway(settings, make_client(handler))).get("/api/status").json()
    assert body["access"]["ok"] is False and body["allOk"] is False


def test_database_has_the_expected_tables(settings):
    create_gateway(settings, make_client(all_up()))
    assert {"assets", "requests", "grants"} <= set(table_names(settings.data_dir / "ephemere.db"))
