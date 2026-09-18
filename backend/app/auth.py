from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Header, HTTPException
from pydantic import BaseModel, Field
from redis.asyncio import Redis
from sqlalchemy import select

from .config import settings


@dataclass(frozen=True)
class Principal:
    actor: str
    role: str
    workspace_id: str
    user_id: str | None = None


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=256)
    workspace_id: str = Field(default="default", min_length=1, max_length=100)


def _sign(payload: str) -> str:
    return hmac.new(settings.AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()


def issue_token(actor: str, role: str, workspace_id: str, user_id: str | None = None, hours: int | None = None) -> str:
    expires = int((datetime.now(timezone.utc) + timedelta(hours=hours if hours is not None else settings.SESSION_HOURS)).timestamp())
    uid = user_id or ""
    sid = session_id or ""
    payload = f"{actor}|{role}|{workspace_id}|{uid}|{expires}|{sid}"
    return f"{payload}|{_sign(payload)}"


def principal_from_token(token: str) -> Principal:
    parts = token.split("|")
    if len(parts) != 7:
        raise HTTPException(401, "Invalid authentication token")
    actor, role, workspace_id, user_id, expiry, session_id, signature = parts
    payload = "|".join(parts[:6])
    try:
        valid = int(expiry) >= int(datetime.now(timezone.utc).timestamp())
    except ValueError:
        valid = False
    if not valid or not hmac.compare_digest(signature, _sign(payload)):
        raise HTTPException(401, "Authentication token expired or invalid")
    if not user_id or not session_id:
        raise HTTPException(401, "Authentication token missing session identity")
    return Principal(actor, role, workspace_id, user_id, session_id)


async def current_principal(authorization: str | None = Header(default=None)) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authentication required")
    principal = principal_from_token(authorization[7:].strip())
    from .database import SessionLocal
    from .models import User, WorkspaceMember

    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.id == principal.user_id, User.is_active.is_(True)))
        member = await db.scalar(select(WorkspaceMember).where(
            WorkspaceMember.user_id == principal.user_id,
            WorkspaceMember.workspace_id == principal.workspace_id,
        ))
        from .models import AuthSession
        session = await db.scalar(select(AuthSession).where(
            AuthSession.id == principal.session_id, AuthSession.user_id == principal.user_id,
            AuthSession.workspace_id == principal.workspace_id, AuthSession.revoked_at.is_(None),
            AuthSession.expires_at >= datetime.now(timezone.utc),
        ))
    if not user or not member or not session:
        raise HTTPException(401, "Session is no longer active")
    session.last_seen_at = datetime.now(timezone.utc)
    await db.commit()
    return Principal(user.email, member.role, member.workspace_id, user.id, principal.session_id)


WS_TICKET_TTL_SECONDS = settings.WS_TICKET_TTL_SECONDS


def _ws_encode(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    body = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return f"ws.{body}.{_sign(body)}"


def _ws_decode(token: str) -> dict:
    try:
        prefix, body, signature = token.split(".", 2)
        if prefix != "ws" or not hmac.compare_digest(signature, _sign(body)):
            raise ValueError
        padded = body + "=" * ((4 - len(body) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    except Exception as exc:
        raise HTTPException(401, "Invalid WebSocket ticket") from exc


async def issue_ws_ticket(principal: Principal, scan_id: str) -> str:
    nonce = secrets.token_urlsafe(24)
    exp = int((datetime.now(timezone.utc) + timedelta(seconds=WS_TICKET_TTL_SECONDS)).timestamp())
    payload = {
        "purpose": "scan.websocket",
        "scan_id": scan_id,
        "workspace_id": principal.workspace_id,
        "user_id": principal.user_id,
        "actor": principal.actor,
        "exp": exp,
        "nonce": nonce,
    }
    client = Redis.from_url(os.getenv("PHANTOM_REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
    try:
        created = await client.set(f"phantom:ws-ticket:{nonce}", "1", ex=WS_TICKET_TTL_SECONDS, nx=True)
    finally:
        await client.aclose()
    if not created:
        raise HTTPException(503, "Unable to issue WebSocket ticket")
    return _ws_encode(payload)


async def consume_ws_ticket(token: str, expected_scan_id: str) -> Principal:
    payload = _ws_decode(token)
    now = int(datetime.now(timezone.utc).timestamp())
    try:
        expires = int(payload.get("exp", 0))
    except (ValueError, TypeError):
        expires = 0
    if payload.get("purpose") != "scan.websocket" or payload.get("scan_id") != expected_scan_id or expires < now or not payload.get("nonce"):
        raise HTTPException(401, "WebSocket ticket expired or out of scope")

    client = Redis.from_url(os.getenv("PHANTOM_REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
    try:
        consumed = await client.getdel(f"phantom:ws-ticket:{payload['nonce']}")
    finally:
        await client.aclose()
    if consumed != "1":
        raise HTTPException(401, "WebSocket ticket already used or invalid")

    from .database import SessionLocal
    from .models import User, WorkspaceMember

    user_id = str(payload.get("user_id", ""))
    workspace_id = str(payload.get("workspace_id", ""))
    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.id == user_id, User.is_active.is_(True)))
        member = await db.scalar(select(WorkspaceMember).where(WorkspaceMember.user_id == user_id, WorkspaceMember.workspace_id == workspace_id))
    if not user or not member:
        raise HTTPException(401, "WebSocket session is no longer active")
    return Principal(user.email, member.role, workspace_id, user_id)
