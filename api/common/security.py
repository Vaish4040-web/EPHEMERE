"""The 'internal door': proxy and access service only accept calls that carry the shared secret."""
import hmac

from fastapi import Header

from .errors import ApiError


def internal_auth(secret: str):
    def check(x_internal_secret: str | None = Header(default=None)):
        if not x_internal_secret:
            raise ApiError(401, "UNAUTHENTICATED", "Missing internal secret.")
        if not hmac.compare_digest(x_internal_secret.encode(), secret.encode()):
            raise ApiError(403, "FORBIDDEN", "Wrong internal secret.")
    return check
