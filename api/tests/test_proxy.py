"""M3 tests, proxy (written BEFORE the code): it holds kfrags, makes cfrags, and refuses after revoke or expiry.
It must never be able to read a file."""
import os
import uuid

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient
from umbral_pre import CapsuleFrag, Capsule, KeyFrag, PublicKey, SecretKey, decrypt_reencrypted

from api.common.config import Settings
from api.proxy.main import create_app as create_proxy
from api.tests.helpers import FakeClock, Owner, b64

SECRET = "test-secret-0123456789abcdef"
GOOD = {"X-Internal-Secret": SECRET}


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def settings(tmp_path):
    return Settings(internal_secret=SECRET, data_dir=tmp_path)


@pytest.fixture
def proxy(settings, clock):
    return TestClient(create_proxy(settings, clock=clock))


class World:
    """An owner, a delegate (the access service) and one encrypted file."""

    def __init__(self):
        self.owner = Owner()
        self.delegate_sk = SecretKey.random()
        self.delegate_pk = self.delegate_sk.public_key()
        self.asset_id = str(uuid.uuid4())
        self.plain = b"the secret profile"
        self.enc = self.owner.encrypt_file(self.plain, self.asset_id)

    def policy(self, grant_id="g1", expires=1_700_000_600, kfrag_bytes=None, **over):
        body = {
            "grantId": grant_id,
            "kfrags": [b64(k) for k in (kfrag_bytes if kfrag_bytes is not None else self.owner.kfrags_for(self.delegate_pk))],
            "expiresAt": expires,
            "ownerPk": b64(self.owner.pk.to_compressed_bytes()),
            "verifyingPk": b64(self.owner.verifying_pk.to_compressed_bytes()),
            "delegatePk": b64(self.delegate_pk.to_compressed_bytes()),
        }
        body.update(over)
        return body

    def reencrypt_body(self, grant_id="g1"):
        return {"grantId": grant_id, "capsule": b64(self.enc["capsule"])}

    def open_with(self, cfrags_b64):
        """What the access service does with what the proxy returned."""
        capsule = Capsule.from_bytes(self.enc["capsule"])
        verified = [CapsuleFrag.from_bytes(__import__("base64").b64decode(c)).verify(
            capsule, self.owner.verifying_pk, self.owner.pk, self.delegate_pk) for c in cfrags_b64]
        dek = decrypt_reencrypted(self.delegate_sk, self.owner.pk, capsule, verified, self.enc["wrappedDek"])
        return AESGCM(bytes(dek)).decrypt(self.enc["iv"], self.enc["ciphertext"], self.asset_id.encode())


@pytest.fixture
def w():
    return World()


# ------------------------------------------------------------------ the internal door
def test_every_proxy_door_needs_the_secret(proxy, w):
    calls = [("POST", "/internal/policies", w.policy()), ("POST", "/internal/reencrypt", w.reencrypt_body()),
             ("DELETE", "/internal/policies/g1", None)]
    for method, path, body in calls:
        assert proxy.request(method, path, json=body).status_code == 401
        assert proxy.request(method, path, json=body, headers={"X-Internal-Secret": "z" * 30}).status_code == 403


# --------------------------------------------------------------------- normal use
def test_proxy_makes_cfrags_that_really_open_the_file(proxy, w):
    assert proxy.post("/internal/policies", json=w.policy(), headers=GOOD).status_code == 201
    r = proxy.post("/internal/reencrypt", json=w.reencrypt_body(), headers=GOOD)
    assert r.status_code == 200 and len(r.json()["cfrags"]) == 1
    assert w.open_with(r.json()["cfrags"]) == w.plain


def test_proxy_never_returns_keys_or_file_content(proxy, w):
    proxy.post("/internal/policies", json=w.policy(), headers=GOOD)
    text = proxy.post("/internal/reencrypt", json=w.reencrypt_body(), headers=GOOD).text
    assert w.plain.decode() not in text and b64(w.enc["wrappedDek"]) not in text


def test_unknown_grant_is_not_found(proxy, w):
    r = proxy.post("/internal/reencrypt", json=w.reencrypt_body("nope"), headers=GOOD)
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"


# ------------------------------------------------------------ kfrags must be genuine
def test_kfrags_made_for_someone_else_are_refused(proxy, w):
    other = SecretKey.random().public_key()
    r = proxy.post("/internal/policies", json=w.policy(kfrag_bytes=w.owner.kfrags_for(other)), headers=GOOD)
    assert r.status_code == 422 and r.json()["error"]["code"] == "BAD_KFRAG"


def test_kfrags_signed_by_a_different_owner_are_refused(proxy, w):
    stranger = Owner()
    r = proxy.post("/internal/policies", json=w.policy(kfrag_bytes=stranger.kfrags_for(w.delegate_pk)), headers=GOOD)
    assert r.status_code == 422 and r.json()["error"]["code"] == "BAD_KFRAG"


def test_garbage_kfrags_are_refused(proxy, w):
    r = proxy.post("/internal/policies", json=w.policy(kfrag_bytes=[os.urandom(310)]), headers=GOOD)
    assert r.status_code == 422 and r.json()["error"]["code"] == "BAD_KFRAG"


@pytest.mark.parametrize("bad", [
    {"kfrags": []}, {"expiresAt": "tomorrow"}, {"ownerPk": b64(os.urandom(32))}, {"grantId": ""},
    {"delegatePk": "***"}, {"kfrags": ["***not base64***"]},
])
def test_badly_formed_policies_are_refused(proxy, w, bad):
    r = proxy.post("/internal/policies", json=w.policy(**bad), headers=GOOD)
    assert r.status_code == 422 and r.json()["error"]["code"] == "BAD_REQUEST"


# ------------------------------------------------------------------------- expiry
def test_expiry_is_enforced_by_the_proxy(proxy, w, clock):
    proxy.post("/internal/policies", json=w.policy(expires=int(clock.now) + 600), headers=GOOD)
    assert proxy.post("/internal/reencrypt", json=w.reencrypt_body(), headers=GOOD).status_code == 200
    clock.advance(599)
    assert proxy.post("/internal/reencrypt", json=w.reencrypt_body(), headers=GOOD).status_code == 200
    clock.advance(1)
    r = proxy.post("/internal/reencrypt", json=w.reencrypt_body(), headers=GOOD)
    assert r.status_code == 403 and r.json()["error"]["code"] == "GRANT_EXPIRED"


def test_a_policy_that_is_already_expired_is_refused(proxy, w, clock):
    r = proxy.post("/internal/policies", json=w.policy(expires=int(clock.now) - 1), headers=GOOD)
    assert r.status_code == 422 and r.json()["error"]["code"] == "BAD_REQUEST"


# ------------------------------------------------------------------- revocation
def test_revoke_stops_access_at_once(proxy, w):
    proxy.post("/internal/policies", json=w.policy(), headers=GOOD)
    assert proxy.delete("/internal/policies/g1", headers=GOOD).status_code == 200
    r = proxy.post("/internal/reencrypt", json=w.reencrypt_body(), headers=GOOD)
    assert r.status_code == 403 and r.json()["error"]["code"] == "GRANT_REVOKED"


def test_revoking_twice_is_fine(proxy, w):
    proxy.post("/internal/policies", json=w.policy(), headers=GOOD)
    assert proxy.delete("/internal/policies/g1", headers=GOOD).status_code == 200
    assert proxy.delete("/internal/policies/g1", headers=GOOD).status_code == 200


def test_a_revoked_grant_cannot_be_switched_back_on(proxy, w):
    proxy.post("/internal/policies", json=w.policy(), headers=GOOD)
    proxy.delete("/internal/policies/g1", headers=GOOD)
    r = proxy.post("/internal/policies", json=w.policy(), headers=GOOD)
    assert r.status_code == 403 and r.json()["error"]["code"] == "GRANT_REVOKED"


def test_a_revoked_kfrag_cannot_come_back_under_a_new_grant_id(proxy, w):
    kfrags = w.owner.kfrags_for(w.delegate_pk)
    proxy.post("/internal/policies", json=w.policy(kfrag_bytes=kfrags), headers=GOOD)
    proxy.delete("/internal/policies/g1", headers=GOOD)
    r = proxy.post("/internal/policies", json=w.policy(grant_id="g2", kfrag_bytes=kfrags), headers=GOOD)
    assert r.status_code == 403 and r.json()["error"]["code"] == "KFRAG_REVOKED"


def test_revoking_an_unknown_grant_still_blocks_that_id_later(proxy, w):
    assert proxy.delete("/internal/policies/g9", headers=GOOD).status_code == 200
    r = proxy.post("/internal/policies", json=w.policy(grant_id="g9"), headers=GOOD)
    assert r.status_code == 403 and r.json()["error"]["code"] == "GRANT_REVOKED"


# ------------------------------------------------------------ surviving a restart
def test_policies_and_revocations_survive_a_restart(settings, clock, w):
    first = TestClient(create_proxy(settings, clock=clock))
    first.post("/internal/policies", json=w.policy(grant_id="live"), headers=GOOD)
    kfrags = w.owner.kfrags_for(w.delegate_pk)
    first.post("/internal/policies", json=w.policy(grant_id="dead", kfrag_bytes=kfrags), headers=GOOD)
    first.delete("/internal/policies/dead", headers=GOOD)

    second = TestClient(create_proxy(settings, clock=clock))          # the "restart"
    r = second.post("/internal/reencrypt", json=w.reencrypt_body("live"), headers=GOOD)
    assert r.status_code == 200 and w.open_with(r.json()["cfrags"]) == w.plain
    assert second.post("/internal/reencrypt", json=w.reencrypt_body("dead"), headers=GOOD).status_code == 403
    again = second.post("/internal/policies", json=w.policy(grant_id="new", kfrag_bytes=kfrags), headers=GOOD)
    assert again.status_code == 403 and again.json()["error"]["code"] == "KFRAG_REVOKED"


def test_several_kfrags_in_one_policy_give_several_cfrags(proxy, w):
    proxy.post("/internal/policies", json=w.policy(kfrag_bytes=w.owner.kfrags_for(w.delegate_pk, 2, 3)), headers=GOOD)
    r = proxy.post("/internal/reencrypt", json=w.reencrypt_body(), headers=GOOD)
    assert len(r.json()["cfrags"]) == 3
    assert w.open_with(r.json()["cfrags"][:2]) == w.plain
