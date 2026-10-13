"""How the gateway talks to the proxy and the access service (the 'internal door': shared secret in a header).
Their error codes are translated into answers that are safe and clear for a browser or a company."""
import httpx

from api.common.config import Settings
from api.common.errors import ApiError

# internal code -> (status, public code, message)
TRANSLATE = {
    "GRANT_REVOKED": (403, "GRANT_REVOKED", "The person has withdrawn this permission."),
    "GRANT_EXPIRED": (403, "GRANT_EXPIRED", "This permission has ended."),
    "KFRAG_REVOKED": (403, "KFRAG_REVOKED", "These permission pieces were revoked before."),
    "BAD_KFRAG": (422, "BAD_KFRAG", "These permission pieces are not valid for this file."),
    "FIELD_NOT_FOUND": (404, "FIELD_NOT_FOUND", "The file does not contain that field."),
}
GENERIC = (502, "ACCESS_FAILED", "The data could not be provided.")


class InternalClient:
    def __init__(self, http: httpx.AsyncClient, settings: Settings):
        self.http, self.s = http, settings
        self.headers = {"X-Internal-Secret": settings.internal_secret}

    async def _call(self, method: str, url: str, *, json=None, missing: ApiError | None = None):
        try:
            r = await self.http.request(method, url, json=json, headers=self.headers, timeout=60)
        except Exception:
            raise ApiError(502, "SERVICE_UNAVAILABLE", "A required internal service is not available right now.")
        if r.status_code < 400:
            return r.json()
        try:
            code = r.json()["error"]["code"]
        except Exception:
            code = "ERROR"
        if code == "NOT_FOUND" and missing is not None:
            raise missing
        status, public, message = TRANSLATE.get(code, GENERIC)
        raise ApiError(status, public, message)

    async def access_public_key(self) -> str:
        return (await self._call("GET", f"{self.s.access_url}/internal/public-key"))["publicKey"]

    async def proxy_store(self, grant_id, kfrags, expires_at, owner_pk, verifying_pk, delegate_pk):
        await self._call("POST", f"{self.s.proxy_url}/internal/policies", json={
            "grantId": grant_id, "kfrags": kfrags, "expiresAt": expires_at,
            "ownerPk": owner_pk, "verifyingPk": verifying_pk, "delegatePk": delegate_pk})

    async def proxy_reencrypt(self, grant_id, capsule) -> list[str]:
        gone = ApiError(403, "GRANT_UNAVAILABLE", "The permission is no longer available. Ask the person to approve again.")
        return (await self._call("POST", f"{self.s.proxy_url}/internal/reencrypt",
                                 json={"grantId": grant_id, "capsule": capsule}, missing=gone))["cfrags"]

    async def proxy_revoke(self, grant_id):
        await self._call("DELETE", f"{self.s.proxy_url}/internal/policies/{grant_id}")

    async def access_open(self, payload: dict) -> dict:
        return await self._call("POST", f"{self.s.access_url}/internal/open", json=payload)
