from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header, HTTPException
from pydantic import BaseModel, Field

from .config import settings

@dataclass(frozen=True)
class Principal:
    actor: str
    role: str
    workspace_id: str

class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=256)
    workspace_id: str = Field(default="default", min_length=1, max_length=100)

# Development bootstrap credentials. Production must replace this with an external
# identity provider or a persistent password-hash user store.
def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

_BOOTSTRAP_PASSWORD = settings.BOOTSTRAP_PASSWORD


def _sign(payload: str) -> str:
    return hmac.new(settings.AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()


def issue_token(actor: str, role: str, workspace_id: str) -> str:
    expires = int((datetime.now(timezone.utc) + timedelta(hours=settings.SESSION_HOURS)).timestamp())
    payload = f"{actor}|{role}|{workspace_id}|{expires}"
    return f"{payload}|{_sign(payload)}"


def principal_from_token(token: str) -> Principal:
    parts = token.split("|")
    if len(parts) != 5:
        raise HTTPException(401, "Invalid authentication token")
    actor, role, workspace_id, expiry, signature = parts
    payload = "|".join(parts[:4])
    if not hmac.compare_digest(signature, _sign(payload)) or int(expiry) < int(datetime.now(timezone.utc).timestamp()):
        raise HTTPException(401, "Authentication token expired or invalid")
    return Principal(actor, role, workspace_id)


def authenticate(email: str, password: str, workspace_id: str) -> Principal | None:
    if email.strip().lower() != settings.BOOTSTRAP_EMAIL.lower() or not hmac.compare_digest(_digest(password), _digest(_BOOTSTRAP_PASSWORD)):
        return None
    return Principal(email.strip().lower(), settings.BOOTSTRAP_ROLE, workspace_id)

async def current_principal(authorization: str | None = Header(default=None)) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authentication required")
    return principal_from_token(authorization[7:].strip())
