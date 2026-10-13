"""M3 tests, access service (written BEFORE the code): it opens a file IN MEMORY and returns only the one
field that was asked for. It never returns the file, never logs it and never writes it to disk."""
import base64
import logging
import os

import pytest
from fastapi.testclient import TestClient
from umbral_pre import Capsule, KeyFrag, PublicKey, SecretKey, reencrypt

from api.access.main import create_app as create_access
from api.common.config import Settings
from api.tests.helpers import Owner, PROFILE, PROFILE_BYTES, b64

SECRET = "test-secret-0123456789abcdef"
GOOD = {"X-Internal-Secret": SECRET}
ASSET = "11111111-1111-4111-8111-111111111111"
OTHER_ASSET = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def settings(tmp_path):
    return Settings(internal_secret=SECRET, data_dir=tmp_path)


@pytest.fixture
def access(settings):
    return TestClient(create_access(settings))


class Case:
    def __init__(self, access, plaintext=PROFILE_BYTES, asset_id=ASSET):
        self.owner = Owner()
        self.asset_id = asset_id
        self.enc = self.owner.encrypt_file(plaintext, asset_id)
        pk = PublicKey.from_compressed_bytes(base64.b64decode(access.get("/internal/public-key", headers=GOOD).json()["publicKey"]))
        capsule = Capsule.from_bytes(self.enc["capsule"])
        self.cfrags = []
        for kb in self.owner.kfrags_for(pk):
            vk = KeyFrag.from_bytes(kb).verify(self.owner.verifying_pk, self.owner.pk, pk)
            self.cfrags.append(bytes(reencrypt(capsule, vk)))

    def body(self, field="address", **over):
        body = {
            "assetId": self.asset_id, "field": field, "capsule": b64(self.enc["capsule"]),
            "wrappedDek": b64(self.enc["wrappedDek"]), "iv": b64(self.enc["iv"]),
            "ownerPk": b64(self.owner.pk.to_compressed_bytes()),
            "verifyingPk": b64(self.owner.verifying_pk.to_compressed_bytes()),
            "ciphertext": b64(self.enc["ciphertext"]), "cfrags": [b64(c) for c in self.cfrags],
        }
        body.update(over)
        return body


def test_the_door_needs_the_secret(access):
    case = Case(access)
    assert access.post("/internal/open", json=case.body()).status_code == 401
    assert access.post("/internal/open", json=case.body(), headers={"X-Internal-Secret": "z" * 30}).status_code == 403


@pytest.mark.parametrize("field", ["address", "name", "phone", "blood_group"])
def test_open_returns_only_the_requested_field(access, field):
    r = access.post("/internal/open", json=Case(access).body(field), headers=GOOD)
    assert r.status_code == 200
    assert r.json() == {"field": field, "value": PROFILE[field]}
    for other, value in PROFILE.items():
        if other != field:
            assert value not in r.text


def test_a_field_that_is_not_in_the_file_is_reported(access):
    case = Case(access, plaintext=b'{"name": "Asha Demo"}')
    r = access.post("/internal/open", json=case.body("phone"), headers=GOOD)
    assert r.status_code == 404 and r.json()["error"]["code"] == "FIELD_NOT_FOUND"


@pytest.mark.parametrize("field", ["password", "ssn", "__proto__", "", "Address", "address "])
def test_only_known_fields_can_be_asked_for(access, field):
    r = access.post("/internal/open", json=Case(access).body(field), headers=GOOD)
    assert r.status_code == 422 and r.json()["error"]["code"] == "BAD_REQUEST"


def test_changed_ciphertext_is_rejected(access):
    case = Case(access)
    bad = bytearray(case.enc["ciphertext"]); bad[5] ^= 1
    r = access.post("/internal/open", json=case.body(ciphertext=b64(bytes(bad))), headers=GOOD)
    assert r.status_code == 422 and r.json()["error"]["code"] == "DECRYPT_FAILED"
    assert "Rosewood" not in r.text


def test_a_file_cannot_be_passed_off_as_another_asset(access):
    r = access.post("/internal/open", json=Case(access).body(assetId=OTHER_ASSET), headers=GOOD)
    assert r.status_code == 422 and r.json()["error"]["code"] == "DECRYPT_FAILED"


def test_cfrags_made_for_a_different_delegate_are_rejected(settings, tmp_path_factory):
    other_settings = Settings(internal_secret=SECRET, data_dir=tmp_path_factory.mktemp("other"))
    other = TestClient(create_access(other_settings))
    case_for_other = Case(other)                                  # cfrags are bound to the OTHER service's key
    mine = TestClient(create_access(settings))
    r = mine.post("/internal/open", json=case_for_other.body(), headers=GOOD)
    assert r.status_code == 403 and r.json()["error"]["code"] == "CFRAG_INVALID"


def test_opening_needs_at_least_one_cfrag(access):
    r = access.post("/internal/open", json=Case(access).body(cfrags=[]), headers=GOOD)
    assert r.status_code == 422 and r.json()["error"]["code"] == "BAD_REQUEST"


@pytest.mark.parametrize("content", [b"not json at all", b'["a", "list"]', b'"just text"'])
def test_files_that_are_not_a_json_object_are_rejected(access, content):
    r = access.post("/internal/open", json=Case(access, plaintext=content).body(), headers=GOOD)
    assert r.status_code == 422 and r.json()["error"]["code"] == "BAD_FILE"


def test_values_that_are_too_big_or_nested_are_refused(access):
    big = Case(access, plaintext=b'{"address": "' + b"x" * 2001 + b'"}')
    r = access.post("/internal/open", json=big.body(), headers=GOOD)
    assert r.status_code == 422 and r.json()["error"]["code"] == "FIELD_TOO_LARGE"
    nested = Case(access, plaintext=b'{"address": {"street": "x", "ssn": "y"}}')
    r = access.post("/internal/open", json=nested.body(), headers=GOOD)
    assert r.status_code == 422 and r.json()["error"]["code"] == "FIELD_TYPE_NOT_ALLOWED"


# ---------------------------------------------------------------- no leaks anywhere
def test_plaintext_never_reaches_the_logs(access, caplog):
    caplog.set_level(logging.DEBUG)
    case = Case(access)
    access.post("/internal/open", json=case.body(), headers=GOOD)
    access.post("/internal/open", json=case.body(ciphertext=b64(os.urandom(100))), headers=GOOD)   # an error path too
    for secret in ("Rosewood", "Bengaluru", "Asha Demo", "90000", "O+"):
        assert secret not in caplog.text


def test_plaintext_never_reaches_the_disk(access, settings):
    access.post("/internal/open", json=Case(access).body(), headers=GOOD)
    for path in settings.data_dir.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert b"Rosewood" not in data and b"Bengaluru" not in data


def test_error_answers_never_contain_file_content(access):
    case = Case(access)
    for body in (case.body("phone", cfrags=[b64(os.urandom(100))]), case.body(wrappedDek=b64(os.urandom(60)))):
        text = access.post("/internal/open", json=body, headers=GOOD).text
        assert "Rosewood" not in text and "Bengaluru" not in text
