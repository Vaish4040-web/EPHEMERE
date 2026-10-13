"""M2 tests (written BEFORE the code): Asha uploads an encrypted file, the gateway stores it in IPFS,
and only the owner can list or fetch it.

Run from the repo root:   python -m pytest -q
"""
import base64
import hashlib
import os
import sqlite3
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from api.common.config import Settings
from api.gateway.db import init_db
from api.gateway.main import create_app as create_gateway
from api.tests.helpers import FakeIpfs

SECRET = "test-secret-0123456789abcdef"
b64 = lambda b: base64.b64encode(b).decode()


@pytest.fixture
def ipfs():
    return FakeIpfs()


@pytest.fixture
def settings(tmp_path):
    return Settings(internal_secret=SECRET, data_dir=tmp_path)


@pytest.fixture
def client(settings, ipfs):
    app = create_gateway(settings, httpx.AsyncClient(transport=httpx.MockTransport(ipfs.handler)))
    return TestClient(app)


def login(c, account):
    r = c.post("/api/demo/login", json={"account": account})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def payload(**over):
    body = {
        "assetId": str(uuid.uuid4()), "label": "profile.json", "iv": b64(os.urandom(12)),
        "capsule": b64(os.urandom(105)), "wrappedDek": b64(os.urandom(60)),
        "ownerPk": b64(os.urandom(33)), "verifyingPk": b64(os.urandom(33)),
        "ciphertext": b64(os.urandom(500)),
    }
    body.update(over)
    return body


# ------------------------------------------------------------------ demo login
def test_demo_login_gives_each_account_a_token_and_role(client):
    asha = client.post("/api/demo/login", json={"account": "asha"}).json()
    org = client.post("/api/demo/login", json={"account": "quickdeliver"}).json()
    assert asha["account"]["role"] == "user" and asha["account"]["name"] == "Asha"
    assert org["account"]["role"] == "org" and org["account"]["name"] == "QuickDeliver"
    assert asha["token"] != org["token"] and len(asha["token"]) >= 30


def test_demo_login_rejects_unknown_accounts(client):
    r = client.post("/api/demo/login", json={"account": "mallory"})
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"


def test_demo_login_can_be_switched_off(tmp_path, ipfs):
    s = Settings(internal_secret=SECRET, data_dir=tmp_path, demo_login=False)
    c = TestClient(create_gateway(s, httpx.AsyncClient(transport=httpx.MockTransport(ipfs.handler))))
    assert c.post("/api/demo/login", json={"account": "asha"}).status_code == 404


# ----------------------------------------------------------------- who may do what
def test_asset_endpoints_need_a_valid_token(client):
    for headers in ({}, {"Authorization": "Bearer not-a-real-token"}, {"Authorization": "Basic abc"}):
        r = client.get("/api/assets", headers=headers)
        assert r.status_code == 401 and r.json()["error"]["code"] == "UNAUTHENTICATED"


def test_organisations_cannot_upload_or_list_files(client):
    org = login(client, "quickdeliver")
    assert client.post("/api/assets", json=payload(), headers=org).status_code == 403
    r = client.get("/api/assets", headers=org)
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"


# --------------------------------------------------------------------- uploading
def test_upload_stores_exactly_the_ciphertext_in_ipfs(client, ipfs):
    asha = login(client, "asha")
    cipher = os.urandom(777)
    r = client.post("/api/assets", json=payload(ciphertext=b64(cipher)), headers=asha)
    assert r.status_code == 201
    body = r.json()
    assert body["cid"].startswith("baf") and body["sizeBytes"] == 777
    assert ipfs.blocks[body["cid"]] == cipher


def test_the_database_holds_only_metadata_never_the_file_bytes(client, settings):
    asha = login(client, "asha")
    cipher = os.urandom(2000)
    client.post("/api/assets", json=payload(ciphertext=b64(cipher)), headers=asha)
    raw = (settings.data_dir / "ephemere.db").read_bytes()
    assert cipher[:64] not in raw


def test_duplicate_asset_id_is_refused(client):
    asha = login(client, "asha")
    p = payload()
    assert client.post("/api/assets", json=p, headers=asha).status_code == 201
    r = client.post("/api/assets", json=p, headers=asha)
    assert r.status_code == 409 and r.json()["error"]["code"] == "CONFLICT"


@pytest.mark.parametrize("bad", [
    {"assetId": "not-a-uuid"},
    {"assetId": "3F2B8C1E-5A47-4D1C-9B6E-7A1D2C3E4F50"},          # upper case is refused
    {"label": ""},
    {"label": "x" * 41},
    {"label": "Asha's blood test <script>"},                      # only safe characters
    {"iv": b64(os.urandom(11))},                                   # IV must be exactly 12 bytes
    {"ownerPk": b64(os.urandom(32))},                              # public keys are 33 bytes
    {"verifyingPk": b64(os.urandom(34))},
    {"capsule": ""},
    {"wrappedDek": "***not base64***"},
    {"ciphertext": ""},
])
def test_bad_uploads_are_refused_with_a_clear_error(client, bad):
    r = client.post("/api/assets", json=payload(**bad), headers=login(client, "asha"))
    assert r.status_code == 422 and r.json()["error"]["code"] == "BAD_REQUEST"


def test_missing_fields_are_refused(client):
    p = payload()
    del p["ciphertext"]
    assert client.post("/api/assets", json=p, headers=login(client, "asha")).status_code == 422


def test_files_over_5_mb_are_refused(client, ipfs):
    r = client.post("/api/assets", json=payload(ciphertext=b64(b"\0" * 5_000_001)), headers=login(client, "asha"))
    assert r.status_code == 413 and r.json()["error"]["code"] == "FILE_TOO_LARGE"
    assert not ipfs.blocks


# --------------------------------------------------- listing and fetching (privacy)
def test_owner_sees_own_files_and_nobody_else_does(client):
    asha, ravi = login(client, "asha"), login(client, "ravi")
    mine = payload(label="asha-profile")
    client.post("/api/assets", json=mine, headers=asha)
    listed = client.get("/api/assets", headers=asha).json()["assets"]
    assert [a["assetId"] for a in listed] == [mine["assetId"]] and listed[0]["label"] == "asha-profile"
    assert client.get("/api/assets", headers=ravi).json()["assets"] == []


def test_owner_can_fetch_the_pieces_needed_to_open_the_file(client):
    asha = login(client, "asha")
    p = payload()
    client.post("/api/assets", json=p, headers=asha)
    meta = client.get(f"/api/assets/{p['assetId']}", headers=asha).json()
    for k in ("iv", "capsule", "wrappedDek", "ownerPk", "verifyingPk"):
        assert meta[k] == p[k]
    assert meta["cid"].startswith("baf") and "ciphertext" not in meta


def test_ciphertext_download_returns_the_same_bytes(client):
    asha = login(client, "asha")
    cipher = os.urandom(1234)
    p = payload(ciphertext=b64(cipher))
    client.post("/api/assets", json=p, headers=asha)
    r = client.get(f"/api/assets/{p['assetId']}/ciphertext", headers=asha)
    assert r.status_code == 200 and r.content == cipher
    assert r.headers["content-type"].startswith("application/octet-stream")


def test_other_users_cannot_tell_that_a_file_exists(client):
    asha, ravi = login(client, "asha"), login(client, "ravi")
    p = payload()
    client.post("/api/assets", json=p, headers=asha)
    for path in (f"/api/assets/{p['assetId']}", f"/api/assets/{p['assetId']}/ciphertext"):
        r = client.get(path, headers=ravi)
        assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"
    assert client.get(f"/api/assets/{uuid.uuid4()}", headers=asha).status_code == 404


def test_organisations_cannot_fetch_files_directly(client):
    asha, org = login(client, "asha"), login(client, "quickdeliver")
    p = payload()
    client.post("/api/assets", json=p, headers=asha)
    assert client.get(f"/api/assets/{p['assetId']}", headers=org).status_code == 403
    assert client.get(f"/api/assets/{p['assetId']}/ciphertext", headers=org).status_code == 403


# ------------------------------------------------------------- storage trouble
def test_if_storage_is_down_nothing_is_recorded(client, ipfs):
    asha = login(client, "asha")
    ipfs.down = True
    r = client.post("/api/assets", json=payload(), headers=asha)
    assert r.status_code == 502 and r.json()["error"]["code"] == "STORAGE_UNAVAILABLE"
    ipfs.down = False
    assert client.get("/api/assets", headers=asha).json()["assets"] == []


def test_if_storage_answers_nonsense_nothing_is_recorded(client, ipfs):
    asha = login(client, "asha")
    ipfs.garbage = True
    assert client.post("/api/assets", json=payload(), headers=asha).status_code == 502
    ipfs.garbage = False
    assert client.get("/api/assets", headers=asha).json()["assets"] == []


def test_download_reports_storage_trouble_clearly(client, ipfs):
    asha = login(client, "asha")
    p = payload()
    client.post("/api/assets", json=p, headers=asha)
    ipfs.blocks.clear()
    r = client.get(f"/api/assets/{p['assetId']}/ciphertext", headers=asha)
    assert r.status_code == 502 and r.json()["error"]["code"] == "STORAGE_UNAVAILABLE"


# ---------------------------------------------------------------------- database
def test_an_old_m1_database_is_upgraded_safely(tmp_path):
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:      # the M1 sketch: no label column, user_version 0
        conn.executescript("CREATE TABLE assets (id TEXT PRIMARY KEY, owner_id TEXT, cid TEXT);")
    init_db(path)
    with sqlite3.connect(path) as conn:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(assets)")]
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert "label" in cols and "size_bytes" in cols and version >= 2


def test_init_db_keeps_existing_data_when_already_up_to_date(client, settings):
    asha = login(client, "asha")
    client.post("/api/assets", json=payload(), headers=asha)
    init_db(settings.data_dir / "ephemere.db")
    assert len(client.get("/api/assets", headers=asha).json()["assets"]) == 1
