from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Principal
from ..config import settings
from ..database import get_db
from ..models import WorkspaceScope
from ..rbac import require_permission
from ..security_scope import ScopeViolation, scope_snapshot, validate_scope_policy
from .audit import record_audit

router = APIRouter(prefix="/api/v1/scope", tags=["scope"])


class ScopeRequest(BaseModel):
    enabled: bool = False
    authorized_targets: list[str] = Field(default_factory=list, max_length=100)
    excluded_targets: list[str] = Field(default_factory=list, max_length=100)
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443], max_length=64)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"], max_length=64)
    blocked_paths: list[str] = Field(default_factory=list, max_length=64)
    max_requests: int = Field(default=250, ge=1, le=250)
    max_concurrency: int = Field(default=1, ge=1, le=16)
    max_redirects: int = Field(default=3, ge=0, le=5)
    authorization_acknowledged: bool = False


@router.get("")
async def get_scope(
    principal: Principal = Depends(require_permission("scan:view")),
    db: AsyncSession = Depends(get_db),
):
    row = await db.scalar(select(WorkspaceScope).where(WorkspaceScope.workspace_id == principal.workspace_id))
    payload = scope_snapshot(row)
    payload["configured"] = row is not None
    payload["effective_limits"] = {
        "max_requests": min(payload["max_requests"], settings.SCAN_REQUEST_BUDGET),
        "max_concurrency": min(payload["max_concurrency"], settings.MAX_CONCURRENT_SCANS),
        "max_redirects": min(payload["max_redirects"], settings.SCAN_MAX_REDIRECTS),
    }
    return payload


@router.put("")
async def put_scope(
    payload: ScopeRequest,
    request: Request,
    principal: Principal = Depends(require_permission("workspace:manage")),
    db: AsyncSession = Depends(get_db),
):
    try:
        normalized = validate_scope_policy(
            payload.model_dump(),
            max_concurrency=payload.max_concurrency,
            max_requests=payload.max_requests,
            max_redirects=payload.max_redirects,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc)) from exc

    if payload.max_requests > settings.SCAN_REQUEST_BUDGET:
        raise HTTPException(400, f"max_requests cannot exceed the server safety budget of {settings.SCAN_REQUEST_BUDGET}")
    if payload.max_concurrency > settings.MAX_CONCURRENT_SCANS:
        raise HTTPException(400, f"max_concurrency cannot exceed the server limit of {settings.MAX_CONCURRENT_SCANS}")
    if payload.max_redirects > settings.SCAN_MAX_REDIRECTS:
        raise HTTPException(400, f"max_redirects cannot exceed the server limit of {settings.SCAN_MAX_REDIRECTS}")

    row = await db.scalar(select(WorkspaceScope).where(WorkspaceScope.workspace_id == principal.workspace_id))
    now = datetime.now(timezone.utc)
    if row is None:
        row = WorkspaceScope(id=str(uuid4()), workspace_id=principal.workspace_id)
        db.add(row)

    row.enabled = payload.enabled
    row.authorized_targets = normalized["authorized_targets"]
    row.excluded_targets = normalized["excluded_targets"]
    row.allowed_ports = normalized["allowed_ports"]
    row.allowed_paths = normalized["allowed_paths"]
    row.blocked_paths = normalized["blocked_paths"]
    row.max_requests = payload.max_requests
    row.max_concurrency = payload.max_concurrency
    row.max_redirects = payload.max_redirects
    row.authorization_acknowledged = payload.authorization_acknowledged
    row.authorization_acknowledged_at = now if payload.authorization_acknowledged else None
    row.acknowledged_by = principal.user_id if payload.authorization_acknowledged else None

    await record_audit(
        db,
        request,
        "scope.updated",
        "workspace_scope",
        row.id,
        {
            "enabled": row.enabled,
            "authorized_targets": row.authorized_targets,
            "excluded_targets": row.excluded_targets,
            "allowed_ports": row.allowed_ports,
            "allowed_paths": row.allowed_paths,
            "blocked_paths": row.blocked_paths,
            "max_requests": row.max_requests,
            "max_concurrency": row.max_concurrency,
            "max_redirects": row.max_redirects,
            "authorization_acknowledged": row.authorization_acknowledged,
        },
        principal,
    )
    await db.commit()
    await db.refresh(row)
    return {**scope_snapshot(row), "configured": True}


@router.post("/check")
async def check_target(
    target: str,
    principal: Principal = Depends(require_permission("scan:view")),
    db: AsyncSession = Depends(get_db),
):
    row = await db.scalar(select(WorkspaceScope).where(WorkspaceScope.workspace_id == principal.workspace_id))
    if row is None:
        raise HTTPException(409, "Workspace scope has not been configured")
    try:
        from ..security_scope import normalize_target, validate_target
        normalized = normalize_target(target)
        result = validate_target_against_scope(normalized, scope_snapshot(row))
        validate_target(normalized)
        return {"allowed": True, **result}
    except ScopeViolation as exc:
        return {"allowed": False, "reason": str(exc)}
    except HTTPException as exc:
        raise exc


from ..security_scope import validate_target_against_scope
