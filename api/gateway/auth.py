"""DEMO sign-in. There are no passwords: anyone who can reach the gateway can sign in as a demo account.
That is fine for a local demo and is NOT real security (say so in the report). Switch it off with DEMO_LOGIN=off."""
import secrets
from dataclasses import dataclass
from typing import Callable

from fastapi import APIRouter, Depends, Header
from pydantic import BaseModel, ConfigDict

from api.common.errors import ApiError

# Fixed IDs (valid UUIDv4) so the audit log and tests can refer to the same people every time.
ACCOUNTS = {
    "asha": {"id": "3f2b8c1e-5a47-4d1c-9b6e-7a1d2c3e4f50", "role": "user", "name": "Asha"},
    "ravi": {"id": "9c4e1d7a-2b63-4f08-8a15-6d3e7b9c0a21", "role": "user", "name": "Ravi"},
    "quickdeliver": {"id": "b7a6e5d4-c3b2-4a19-8f0e-1d2c3b4a5968", "role": "org", "name": "QuickDeliver"},
    "freshmart": {"id": "d1e2f3a4-b5c6-4d7e-8f90-a1b2c3d4e5f6", "role": "org", "name": "FreshMart"},
}
ACCOUNTS_BY_ID = {a["id"]: a for a in ACCOUNTS.values()}


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    account: str


@dataclass
class AuthKit:
    router: APIRouter
    current_account: Callable
    require_user: Callable
    require_org: Callable


def make_auth(demo_login: bool = True) -> AuthKit:
    sessions: dict[str, dict] = {}      # token -> account (lives in memory; a restart signs everyone out)
    router = APIRouter()

    if demo_login:
        @router.post("/api/demo/login")
        def login(body: LoginBody):
            account = ACCOUNTS.get(body.account)
            if account is None:
                raise ApiError(404, "NOT_FOUND", "Unknown demo account.")
            token = secrets.token_urlsafe(32)
            sessions[token] = account
            return {"token": token, "account": account}

    def current_account(authorization: str | None = Header(default=None)) -> dict:
        if not authorization or not authorization.startswith("Bearer "):
            raise ApiError(401, "UNAUTHENTICATED", "Please sign in.")
        account = sessions.get(authorization[7:])
        if account is None:
            raise ApiError(401, "UNAUTHENTICATED", "Please sign in again.")
        return account

    def require_user(account: dict = Depends(current_account)) -> dict:
        if account["role"] != "user":
            raise ApiError(403, "FORBIDDEN", "Only people can do this, not companies.")
        return account

    def require_org(account: dict = Depends(current_account)) -> dict:
        if account["role"] != "org":
            raise ApiError(403, "FORBIDDEN", "Only companies can do this.")
        return account

    return AuthKit(router, current_account, require_user, require_org)
