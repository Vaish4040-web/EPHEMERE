"""Talks to the local IPFS node (Kubo). The gateway is the ONLY thing that talks to it,
because IPFS's control port must never be reachable from a browser."""
import json
import re

import httpx

from api.common.errors import ApiError

CID_RE = re.compile(r"^baf[a-z2-7]{20,120}$")      # CIDv1 in base32, as made with cid-version=1


def _unavailable() -> ApiError:
    return ApiError(502, "STORAGE_UNAVAILABLE", "The storage service is not available right now.")


class IpfsClient:
    def __init__(self, http: httpx.AsyncClient, base_url: str):
        self.http, self.base = http, base_url.rstrip("/")

    async def add(self, data: bytes) -> str:
        """Store bytes (always CIPHERTEXT) and return their CID."""
        try:
            r = await self.http.post(
                f"{self.base}/api/v0/add",
                params={"cid-version": "1", "raw-leaves": "true", "pin": "true", "quieter": "true"},
                files={"file": ("ciphertext.bin", data, "application/octet-stream")},
                timeout=60,
            )
            r.raise_for_status()
            cid = json.loads(r.text.strip().splitlines()[-1])["Hash"]
        except Exception:
            raise _unavailable()
        if not isinstance(cid, str) or not CID_RE.match(cid):
            raise _unavailable()
        return cid

    async def cat(self, cid: str) -> bytes:
        if not CID_RE.match(cid):
            raise _unavailable()
        try:
            r = await self.http.post(f"{self.base}/api/v0/cat", params={"arg": cid, "timeout": "10s"}, timeout=30)
            r.raise_for_status()
            return r.content
        except Exception:
            raise _unavailable()
