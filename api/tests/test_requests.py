"""M3 tests (written BEFORE the code): QuickDeliver asks, Asha approves, the company gets ONLY the one field.
The real gateway, proxy and access service run together in this process with real cryptography.

Run from the repo root:   python -m pytest -q
"""
import base64
import sqlite3
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient
from umbral_pre import PublicKey

from api.access.main import create_app as create_access
from api.common.config import Settings
from api.gateway.db import init_db
from api.gateway.main import create_app as create_gateway
from api.proxy.main import create_app as create_proxy
from api.tests.helpers import FakeClock, FakeIpfs, Owner, PROFILE, PROFILE_BYTES, Router, b64

SECRET = "test-secret-0123456789abcdef"
ADDRESS = PROFILE["address"]


class System:
    """Gateway + proxy + access service + pretend IPFS, all in one process."""

    def __init__(self, tmp_path):
        self.settings = Settings(internal_secret=SECRET, data_dir=tmp_path)
        self.clock = FakeClock()
        self.ipfs = FakeIpfs()
        self.proxy_db = tmp_path / "proxy.db"
        self.router = Router({
            self.settings.proxy_port: httpx.ASGITransport(app=create_proxy(self.settings, clock=self.clock)),
            self.settings.access_port: httpx.ASGITransport(app=create_access(self.settings)),
            self.settings.ipfs_api_port: httpx.MockTransport(self.ipfs.handler),
        })
        gateway = create_gateway(self.settings, httpx.AsyncClient(transport=self.router), clock=self.clock)
        self.c = TestClient(gateway)

    def restart_proxy(self):
        self.router.routes[self.settings.proxy_port] = httpx.ASGITransport(app=create_proxy(self.settings, clock=self.clock))

    def wipe_proxy(self):
        self.proxy_db.unlink()
        self.restart_proxy()


@pytest.fixture
def system(tmp_path):
    return System(tmp_path)


def headers_for(c, account):
    r = c.post("/api/demo/login", json={"account": account})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


class Person:
    """Asha or Ravi: owns keys (like the browser), uploads files, approves requests."""

    def __init__(self, system, account="asha"):
        self.s, self.c, self.h, self.owner = system, system.c, headers_for(system.c, account), Owner()

    def upload(self, plaintext=PROFILE_BYTES):
        payload = self.owner.asset_payload(plaintext)
        r = self.c.post("/api/assets", json=payload, headers=self.h)
        assert r.status_code == 201, r.text
        return payload["assetId"]

    def access_pk(self):
        r = self.c.get("/api/access-key", headers=self.h)
        assert r.status_code == 200, r.text
        return PublicKey.from_compressed_bytes(base64.b64decode(r.json()["publicKey"]))

    def approve(self, request_id, asset_id, kfrags=None, expect=200):
        kfrags = kfrags if kfrags is not None else self.owner.kfrags_for(self.access_pk())
        r = self.c.post(f"/api/user/requests/{request_id}/approve", headers=self.h,
                        json={"assetId": asset_id, "kfrags": [b64(k) for k in kfrags]})
        assert r.status_code == expect, r.text
        return r

    def deny(self, request_id):
        return self.c.post(f"/api/user/requests/{request_id}/deny", headers=self.h)

    def requests(self):
        return self.c.get("/api/user/requests", headers=self.h).json()["requests"]


class Company:
    def __init__(self, system, account="quickdeliver"):
        self.c, self.h = system.c, headers_for(system.c, account)

    def ask(self, subject="asha", field="address", purpose="DELIVERY", duration=600, expect=201):
        r = self.c.post("/api/org/requests", headers=self.h,
                        json={"subject": subject, "field": field, "purpose": purpose, "durationSec": duration})
        assert r.status_code == expect, r.text
        return r.json().get("requestId") if expect == 201 else r

    def get(self, request_id):
        return self.c.post(f"/api/org/requests/{request_id}/access", headers=self.h)

    def requests(self):
        return self.c.get("/api/org/requests", headers=self.h).json()["requests"]


@pytest.fixture
def asha(system):
    return Person(system, "asha")


@pytest.fixture
def ravi(system):
    return Person(system, "ravi")


@pytest.fixture
def qd(system):
    return Company(system, "quickdeliver")


def approved_request(asha, qd, field="address", purpose="DELIVERY", duration=600, plaintext=PROFILE_BYTES):
    asset = asha.upload(plaintext)
    rid = qd.ask(field=field, purpose=purpose, duration=duration)
    asha.approve(rid, asset)
    return rid, asset


# ============================================================ the rules (policy)
def test_the_rules_are_public_so_pages_can_show_them(system):
    body = system.c.get("/api/policy").json()
    codes = {p["code"]: p for p in body["purposes"]}
    assert set(codes) == {"DELIVERY", "KYC", "CONSULTATION"} and "address" in codes["DELIVERY"]["fields"]
    assert body["minDurationSec"] == 30 and body["maxDurationSec"] == 86400


# ============================================================ asking
def test_a_company_asks_and_the_person_sees_it(system, asha, qd):
    rid = qd.ask()
    mine = asha.requests()
    assert [r["requestId"] for r in mine] == [rid]
    r = mine[0]
    assert (r["org"], r["field"], r["purpose"], r["durationSec"], r["status"]) == ("QuickDeliver", "address", "DELIVERY", 600, "pending")
    assert qd.requests()[0]["status"] == "pending" and qd.requests()[0]["subject"] == "Asha"


@pytest.mark.parametrize("bad", [
    dict(subject="mallory"), dict(subject="quickdeliver"), dict(field="password"), dict(purpose="MARKETING"),
    dict(durationSec=10), dict(durationSec=100_000), dict(durationSec="soon"),
])
def test_bad_requests_are_refused(qd, bad):
    body = {"subject": "asha", "field": "address", "purpose": "DELIVERY", "durationSec": 600, **bad}
    r = qd.c.post("/api/org/requests", headers=qd.h, json=body)
    assert r.status_code in (404, 422), r.text
    assert r.json()["error"]["code"] in ("NOT_FOUND", "BAD_REQUEST")


def test_a_purpose_may_only_ask_for_its_own_fields(qd):
    r = qd.c.post("/api/org/requests", headers=qd.h,
                  json={"subject": "asha", "field": "blood_group", "purpose": "DELIVERY", "durationSec": 600})
    assert r.status_code == 422 and r.json()["error"]["code"] == "PURPOSE_NOT_ALLOWED"


def test_extra_fields_in_a_request_are_refused(qd):
    r = qd.c.post("/api/org/requests", headers=qd.h,
                  json={"subject": "asha", "field": "address", "purpose": "DELIVERY", "durationSec": 600, "everything": True})
    assert r.status_code == 422


def test_who_may_do_what(system, asha, qd):
    rid = qd.ask()
    assert system.c.post("/api/org/requests", headers=asha.h, json={}).status_code == 403          # people cannot ask
    assert system.c.get("/api/org/requests", headers=asha.h).status_code == 403
    assert system.c.get("/api/user/requests", headers=qd.h).status_code == 403                      # companies cannot list people's inbox
    assert system.c.post(f"/api/user/requests/{rid}/deny", headers=qd.h).status_code == 403
    assert system.c.post(f"/api/org/requests/{rid}/access", headers=asha.h).status_code == 403
    for method, path in (("GET", "/api/user/requests"), ("GET", "/api/org/requests"), ("GET", "/api/access-key")):
        assert system.c.request(method, path).status_code == 401


def test_requests_are_private_to_the_two_parties(system, asha, ravi, qd):
    rid = qd.ask()
    other_co = Company(system, "freshmart")
    assert ravi.requests() == [] and other_co.requests() == []
    assert system.c.post(f"/api/user/requests/{rid}/deny", headers=ravi.h).status_code == 404
    assert other_co.get(rid).status_code == 404


# ============================================================ approving
def test_approval_works_and_reports_when_it_ends(system, asha, qd):
    asset = asha.upload()
    rid = qd.ask(duration=600)
    r = asha.approve(rid, asset)
    assert r.json()["status"] == "approved" and r.json()["expiresAt"] == int(system.clock.now) + 600
    assert asha.requests()[0]["status"] == "approved" and qd.requests()[0]["status"] == "approved"


def test_only_your_own_files_can_be_used(system, asha, ravi, qd):
    rid = qd.ask()
    ravis_file = ravi.upload()
    assert system.c.post(f"/api/user/requests/{rid}/approve", headers=asha.h,
                         json={"assetId": ravis_file, "kfrags": [b64(k) for k in asha.owner.kfrags_for(asha.access_pk())]}).status_code == 404
    assert system.c.post(f"/api/user/requests/{rid}/approve", headers=asha.h,
                         json={"assetId": str(uuid.uuid4()), "kfrags": [b64(b"x" * 300)]}).status_code == 404


def test_permission_pieces_for_the_wrong_delegate_are_refused(system, asha, qd):
    from umbral_pre import SecretKey
    asset, rid = asha.upload(), qd.ask()
    r = asha.approve(rid, asset, kfrags=asha.owner.kfrags_for(SecretKey.random().public_key()), expect=422)
    assert r.json()["error"]["code"] == "BAD_KFRAG"
    assert asha.requests()[0]["status"] == "pending"                                                # nothing changed


def test_permission_pieces_from_the_wrong_keys_are_refused(system, asha, qd):
    """Keys that are not the ones the file was encrypted with cannot grant access to it."""
    asset, rid = asha.upload(), qd.ask()
    r = asha.approve(rid, asset, kfrags=Owner().kfrags_for(asha.access_pk()), expect=422)
    assert r.json()["error"]["code"] == "BAD_KFRAG" and asha.requests()[0]["status"] == "pending"


@pytest.mark.parametrize("kfrags", [[], ["***"]])
def test_empty_or_garbled_pieces_are_refused(system, asha, qd, kfrags):
    asset, rid = asha.upload(), qd.ask()
    r = system.c.post(f"/api/user/requests/{rid}/approve", headers=asha.h, json={"assetId": asset, "kfrags": kfrags})
    assert r.status_code == 422 and r.json()["error"]["code"] == "BAD_REQUEST"


def test_a_request_can_only_be_decided_once(system, asha, qd):
    asset, rid = asha.upload(), qd.ask()
    asha.approve(rid, asset)
    assert asha.approve(rid, asset, expect=409).json()["error"]["code"] == "CONFLICT"
    assert asha.deny(rid).status_code == 409
    rid2 = qd.ask()
    assert asha.deny(rid2).status_code == 200
    assert asha.approve(rid2, asset, expect=409).json()["error"]["code"] == "CONFLICT"


# ============================================================ getting the data
def test_no_data_before_a_decision_or_after_a_denial(system, asha, qd):
    asha.upload()
    rid = qd.ask()
    r = qd.get(rid)
    assert r.status_code == 403 and r.json()["error"]["code"] == "REQUEST_NOT_APPROVED"
    asha.deny(rid)
    assert qd.get(rid).json()["error"]["code"] == "REQUEST_NOT_APPROVED"
    assert qd.requests()[0]["status"] == "denied"


def test_the_company_gets_only_the_one_field(asha, qd):
    rid, _ = approved_request(asha, qd)
    r = qd.get(rid)
    assert r.status_code == 200
    assert r.json() == {"requestId": rid, "field": "address", "value": ADDRESS}
    for other in ("Asha Demo", "90000", "O+", "blood_group"):
        assert other not in r.text


def test_it_works_again_while_the_permission_lasts(system, asha, qd):
    rid, _ = approved_request(asha, qd, duration=600)
    system.clock.advance(300)
    assert qd.get(rid).status_code == 200 and qd.get(rid).status_code == 200


def test_each_purpose_gives_only_its_field(asha, qd):
    rid, _ = approved_request(asha, qd, field="blood_group", purpose="CONSULTATION")
    assert qd.get(rid).json()["value"] == "O+"


def test_asking_for_a_field_the_file_does_not_have(asha, qd):
    rid, _ = approved_request(asha, qd, field="phone", plaintext=b'{"name": "Asha Demo"}')
    r = qd.get(rid)
    assert r.status_code == 404 and r.json()["error"]["code"] == "FIELD_NOT_FOUND"


def test_another_company_cannot_use_the_permission(system, asha, qd):
    rid, _ = approved_request(asha, qd)
    assert Company(system, "freshmart").get(rid).status_code == 404


# ============================================================ time and failures
def test_the_permission_ends_when_the_time_is_up(system, asha, qd):
    rid, _ = approved_request(asha, qd, duration=60)
    assert qd.get(rid).status_code == 200
    system.clock.advance(60)
    r = qd.get(rid)
    assert r.status_code == 403 and r.json()["error"]["code"] == "GRANT_EXPIRED"
    assert qd.requests()[0]["status"] == "expired" and asha.requests()[0]["status"] == "expired"


def test_the_proxy_alone_also_enforces_the_time(system, asha, qd):
    """Even if the gateway's own bookkeeping were wrong (here only the PROXY clock moves), the proxy refuses after expiry."""
    rid, _ = approved_request(asha, qd, duration=60)
    from api.tests.helpers import FakeClock
    proxy_clock = FakeClock(system.clock.now + 61)
    system.router.routes[system.settings.proxy_port] = httpx.ASGITransport(app=create_proxy(system.settings, clock=proxy_clock))
    r = qd.get(rid)
    assert r.status_code == 403 and r.json()["error"]["code"] == "GRANT_EXPIRED"


def test_permissions_survive_a_proxy_restart(system, asha, qd):
    rid, _ = approved_request(asha, qd)
    system.restart_proxy()
    assert qd.get(rid).json()["value"] == ADDRESS


def test_a_lost_permission_gives_a_clear_answer(system, asha, qd):
    rid, _ = approved_request(asha, qd)
    system.wipe_proxy()
    r = qd.get(rid)
    assert r.status_code == 403 and r.json()["error"]["code"] == "GRANT_UNAVAILABLE"


def test_missing_stored_file_is_reported_as_a_storage_problem(system, asha, qd):
    rid, _ = approved_request(asha, qd)
    system.ipfs.blocks.clear()
    r = qd.get(rid)
    assert r.status_code == 502 and r.json()["error"]["code"] == "STORAGE_UNAVAILABLE"


def test_a_proxy_that_is_down_gives_a_clear_answer(system, asha, qd):
    rid, _ = approved_request(asha, qd)
    del system.router.routes[system.settings.proxy_port]
    r = qd.get(rid)
    assert r.status_code == 502 and r.json()["error"]["code"] == "SERVICE_UNAVAILABLE"


def test_approving_while_the_proxy_is_down_changes_nothing(system, asha, qd):
    asset, rid = asha.upload(), qd.ask()
    del system.router.routes[system.settings.proxy_port]
    asha.approve(rid, asset, expect=502)
    assert asha.requests()[0]["status"] == "pending"


# ============================================================ access service key
def test_people_can_fetch_the_access_service_public_key(system, asha, qd):
    r = system.c.get("/api/access-key", headers=asha.h)
    assert r.status_code == 200 and len(base64.b64decode(r.json()["publicKey"])) == 33
    assert system.c.get("/api/access-key", headers=qd.h).status_code == 403


# ============================================================ nothing readable is left lying around
def test_no_plaintext_is_stored_anywhere_by_the_backend(system, asha, qd):
    rid, _ = approved_request(asha, qd)
    qd.get(rid)
    for path in system.settings.data_dir.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert b"Rosewood" not in data and b"Bengaluru" not in data and b"Asha Demo" not in data, path
    assert all(b"Rosewood" not in blob for blob in system.ipfs.blocks.values())


def test_list_endpoints_never_contain_file_values(asha, qd):
    rid, _ = approved_request(asha, qd)
    qd.get(rid)
    for text in (str(asha.requests()), str(qd.requests())):
        assert "Rosewood" not in text and "O+" not in text


# ============================================================ database upgrade
def test_upgrading_from_m2_keeps_uploaded_files(tmp_path):
    path = tmp_path / "m2.db"
    init_db(path)
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TABLE requests")
        conn.execute("DROP TABLE grants")
        conn.execute("CREATE TABLE requests (id TEXT PRIMARY KEY, org_id TEXT, asset_id TEXT NOT NULL)")
        conn.execute("CREATE TABLE grants (id TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO assets VALUES ('a1','owner','profile','bafk',10,'iv','cap','wrapped','opk','vpk','2026-01-01T00:00:00Z')")
        conn.execute("PRAGMA user_version = 2")
    init_db(path)
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT id FROM assets").fetchall() == [("a1",)]
        cols = [r[1] for r in conn.execute("PRAGMA table_info(requests)")]
        grant_cols = [r[1] for r in conn.execute("PRAGMA table_info(grants)")]
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
    assert "subject_id" in cols and "expires_epoch" in grant_cols
