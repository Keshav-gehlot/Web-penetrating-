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
from ..models import Scan, WorkspaceScope
from ..observability import record_operational_event
from ..rbac import require_permission
from ..security_scope import (
    ScopeViolation,
    normalize_target,
    scope_snapshot,
    validate_scope_policy,
    validate_target,
    validate_target_against_scope,
)
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
    authorization_reconfirmed: bool = False


def _cancel_scans_for_scope_change(scans, now: datetime) -> list[str]:
    cancelled_ids: list[str] = []
    for scan in scans:
        if scan.status not in {"queued", "running"}:
            continue
        scan.cancel_requested_at = now
        scan.status = "cancelled"
        scan.cancelled_at = now
        scan.completed_at = now
        scan.worker_id = None
        scan.lease_expires_at = None
        scan.error = "Cancelled because the workspace scope policy changed. Re-queue after reviewing the new scope."
        cancelled_ids.append(scan.id)
    return cancelled_ids


def _policy_changed(row: WorkspaceScope | None, normalized: dict, payload: ScopeRequest) -> bool:
    if row is None:
        return True
    return any(
        (
            row.enabled != payload.enabled,
            row.authorized_targets != normalized["authorized_targets"],
            row.excluded_targets != normalized["excluded_targets"],
            row.allowed_ports != normalized["allowed_ports"],
            row.allowed_paths != normalized["allowed_paths"],
            row.blocked_paths != normalized["blocked_paths"],
            row.max_requests != payload.max_requests,
            row.max_concurrency != payload.max_concurrency,
            row.max_redirects != payload.max_redirects,
        )
    )


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

    if payload.enabled and not payload.authorization_acknowledged:
        raise HTTPException(400, "Authorization acknowledgement is required before enabling the scope")
    if payload.max_requests > settings.SCAN_REQUEST_BUDGET:
        raise HTTPException(400, f"max_requests cannot exceed the server safety budget of {settings.SCAN_REQUEST_BUDGET}")
    if payload.max_concurrency > settings.MAX_CONCURRENT_SCANS:
        raise HTTPException(400, f"max_concurrency cannot exceed the server limit of {settings.MAX_CONCURRENT_SCANS}")
    if payload.max_redirects > settings.SCAN_MAX_REDIRECTS:
        raise HTTPException(400, f"max_redirects cannot exceed the server limit of {settings.SCAN_MAX_REDIRECTS}")

    row = await db.scalar(select(WorkspaceScope).where(WorkspaceScope.workspace_id == principal.workspace_id))
    policy_changed = _policy_changed(row, normalized, payload)
    authorization_policy_changed = row is not None and any(
        (
            row.authorized_targets != normalized["authorized_targets"],
            row.excluded_targets != normalized["excluded_targets"],
            row.allowed_ports != normalized["allowed_ports"],
            row.allowed_paths != normalized["allowed_paths"],
            row.blocked_paths != normalized["blocked_paths"],
            row.max_requests != payload.max_requests,
            row.max_concurrency != payload.max_concurrency,
            row.max_redirects != payload.max_redirects,
        )
    )
    if (
        authorization_policy_changed
        and row.authorization_acknowledged
        and payload.authorization_acknowledged
        and not payload.authorization_reconfirmed
    ):
        raise HTTPException(400, "Policy changed. Re-confirm authorization before restoring the acknowledgement.")
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

    cancelled_ids: list[str] = []
    if policy_changed and row.id:
        active = await db.scalars(
            select(Scan).where(
                Scan.workspace_id == principal.workspace_id,
                Scan.status.in_(["queued", "running"]),
            )
        )
        cancelled_ids = _cancel_scans_for_scope_change(active.all(), now)
        for scan_id in cancelled_ids:
            await record_audit(
                db,
                request,
                "scan.scope_cancelled",
                "scan",
                scan_id,
                {"scope_id": row.id, "reason": "workspace scope policy changed"},
                principal,
            )

    await record_audit(
        db,
        request,
        "scope.updated",
        "workspace_scope",
        row.id,
        {
            "enabled": row.enabled,
            "policy_changed": policy_changed,
            "authorized_targets": row.authorized_targets,
            "excluded_targets": row.excluded_targets,
            "allowed_ports": row.allowed_ports,
            "allowed_paths": row.allowed_paths,
            "blocked_paths": row.blocked_paths,
            "max_requests": row.max_requests,
            "max_concurrency": row.max_concurrency,
            "max_redirects": row.max_redirects,
            "authorization_acknowledged": row.authorization_acknowledged,
            "cancelled_scan_count": len(cancelled_ids),
        },
        principal,
    )
    await db.commit()
    await db.refresh(row)

    if cancelled_ids:
        for scan_id in cancelled_ids:
            await record_operational_event(
                "scan.scope_changed",
                "Scan cancelled because workspace scope changed",
                "warning",
                principal.workspace_id,
                scan_id,
                {"scope_id": row.id},
            )

    return {**scope_snapshot(row), "configured": True, "cancelled_scan_count": len(cancelled_ids)}


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
        normalized = normalize_target(target)
        validate_target(normalized)
        result = validate_target_against_scope(normalized, scope_snapshot(row))
        return {"allowed": True, **result}
    except ScopeViolation as exc:
        return {"allowed": False, "reason": str(exc)}
    except HTTPException as exc:
        return {"allowed": False, "reason": str(exc.detail)}
