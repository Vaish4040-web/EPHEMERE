"""Shared test helpers: a pretend IPFS node, and a way to run the gateway, proxy and access service
TOGETHER inside one test process (real code and real cryptography, no network needed)."""
import base64
import hashlib

import httpx


class FakeIpfs:
    """A tiny pretend IPFS node: remembers bytes under a fake content address."""

    def __init__(self):
        self.blocks = {}
        self.down = False
        self.garbage = False

    def handler(self, request: httpx.Request):
        if self.down:
            raise httpx.ConnectError("refused")
        if request.url.path == "/api/v0/add":
            boundary = request.headers["content-type"].split("boundary=")[1].encode()
            part = request.content.split(b"--" + boundary)[1]
            data = part.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n", 1)[0]
            digest = base64.b32encode(hashlib.sha256(data).digest()).decode().lower().rstrip("=")
            cid = "bafkrei" + digest[:52]
            self.blocks[cid] = data
            if self.garbage:
                return httpx.Response(200, text="not json at all")
            return httpx.Response(200, text=f'{{"Name":"ciphertext.bin","Hash":"{cid}","Size":"{len(data)}"}}\n')
        if request.url.path == "/api/v0/cat":
            cid = request.url.params["arg"]
            if cid in self.blocks:
                return httpx.Response(200, content=self.blocks[cid])
            return httpx.Response(500, json={"Message": "block was not found locally"})
        return httpx.Response(404)


class Router(httpx.AsyncBaseTransport):
    """Sends each call to the right in-process service, based on the port the gateway would use."""

    def __init__(self, routes: dict):
        self.routes = routes

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        transport = self.routes.get(request.url.port)
        if transport is None:
            raise httpx.ConnectError(f"no service on port {request.url.port}")
        return await transport.handle_async_request(request)


# ------------------------------------------------------------------ pretend browser
import json
import os
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from umbral_pre import SecretKey, Signer, encrypt, generate_kfrags

b64 = lambda b: base64.b64encode(b).decode()

PROFILE = {
    "name": "Asha Demo",
    "address": "Flat 4B, Rosewood Apartments, Example Road, Bengaluru 560001",
    "phone": "+91 90000 00000",
    "blood_group": "O+",
}
PROFILE_BYTES = json.dumps(PROFILE).encode()


class FakeClock:
    def __init__(self, now=1_700_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class Owner:
    """What Asha's browser does (encrypt a file, wrap its key, make kfrags), written in Python for tests."""

    def __init__(self):
        self.sk = SecretKey.random()
        self.pk = self.sk.public_key()
        self.signer = Signer(SecretKey.random())
        self.verifying_pk = self.signer.verifying_key()

    def encrypt_file(self, plaintext: bytes, asset_id: str) -> dict:
        dek, iv = os.urandom(32), os.urandom(12)
        ciphertext = AESGCM(dek).encrypt(iv, plaintext, asset_id.encode())
        capsule, wrapped = encrypt(self.pk, dek)
        return {"iv": iv, "ciphertext": ciphertext, "capsule": bytes(capsule), "wrappedDek": bytes(wrapped)}

    def kfrags_for(self, delegate_pk, m=1, n=1) -> list[bytes]:
        return [bytes(k) for k in generate_kfrags(self.sk, delegate_pk, self.signer, m, n, True, True)]

    def asset_payload(self, plaintext: bytes = PROFILE_BYTES, asset_id: str | None = None, label="profile.json") -> dict:
        asset_id = asset_id or str(uuid.uuid4())
        e = self.encrypt_file(plaintext, asset_id)
        return {"assetId": asset_id, "label": label, "iv": b64(e["iv"]), "capsule": b64(e["capsule"]),
                "wrappedDek": b64(e["wrappedDek"]), "ownerPk": b64(self.pk.to_compressed_bytes()),
                "verifyingPk": b64(self.verifying_pk.to_compressed_bytes()), "ciphertext": b64(e["ciphertext"])}
