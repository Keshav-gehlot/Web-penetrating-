from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Principal
from ..database import get_db
from ..models import Asset, Scan, Schedule, WorkspaceScope
from ..queue import enqueue_scan
from ..rbac import require_permission
from ..scanners.runner import PROFILES
from ..security_scope import ScopeViolation, normalize_target, scope_snapshot, validate_target, validate_target_against_scope
from .audit import record_audit

router = APIRouter(prefix="/api/v1/schedules", tags=["schedules"])


class ScheduleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    target: str = Field(min_length=1, max_length=2048)
    profile: str = Field(default="standard", pattern="^(quick|standard|deep|trust)$")
    interval_seconds: int = Field(ge=300, le=2_592_000)


def serialize(row: Schedule) -> dict:
    return {
        "id": row.id, "name": row.name, "target": row.target, "profile": row.profile,
        "interval_seconds": row.interval_seconds, "next_run_at": row.next_run_at.isoformat(),
        "enabled": row.enabled, "last_run_at": row.last_run_at.isoformat() if row.last_run_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


async def _scope(db: AsyncSession, workspace_id: str) -> dict[str, object]:
    row = await db.scalar(select(WorkspaceScope).where(WorkspaceScope.workspace_id == workspace_id))
    if row is None:
        raise HTTPException(409, "Workspace scope is not configured. Configure an authorized scope before creating schedules.")
    return scope_snapshot(row)


@router.get("")
async def list_schedules(principal: Principal = Depends(require_permission("scan:view")), db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(Schedule).where(Schedule.workspace_id == principal.workspace_id).order_by(Schedule.next_run_at))
    return [serialize(row) for row in rows.all()]


@router.post("")
async def create_schedule(payload: ScheduleRequest, request: Request, principal: Principal = Depends(require_permission("scan:create")), db: AsyncSession = Depends(get_db)):
    scope = await _scope(db, principal.workspace_id)
    if scope.get("approval_status") != "approved":
        raise HTTPException(409, "Workspace scope must be approved before creating a schedule")
    try:
        normalized = normalize_target(payload.target)
        validate_target_against_scope(normalized, scope)
    except ScopeViolation as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    target = validate_target(normalized)
    row = Schedule(id=str(uuid4()), workspace_id=principal.workspace_id, created_by=principal.user_id,
                   name=payload.name, target=target["target"], profile=payload.profile,
                   interval_seconds=payload.interval_seconds,
                   next_run_at=datetime.now(timezone.utc) + timedelta(seconds=payload.interval_seconds), enabled=True)
    db.add(row)
    await record_audit(db, request, "schedule.created", "schedule", row.id, {"profile": row.profile, "interval_seconds": row.interval_seconds, "scope_id": scope.get("id")}, principal)
    await db.commit(); await db.refresh(row)
    return serialize(row)


@router.patch("/{schedule_id}")
async def toggle_schedule(schedule_id: str, enabled: bool, request: Request, principal: Principal = Depends(require_permission("scan:create")), db: AsyncSession = Depends(get_db)):
    row = await db.scalar(select(Schedule).where(Schedule.id == schedule_id, Schedule.workspace_id == principal.workspace_id))
    if not row: raise HTTPException(404, "Schedule not found")
    if enabled:
        scope = await _scope(db, principal.workspace_id)
        if scope.get("approval_status") != "approved":
            raise HTTPException(409, "Workspace scope must be approved before enabling a schedule")
        try:
            validate_target_against_scope(row.target, scope)
        except ScopeViolation as exc:
            raise HTTPException(403, str(exc)) from exc
    row.enabled = enabled
    if enabled and row.next_run_at < datetime.now(timezone.utc): row.next_run_at = datetime.now(timezone.utc) + timedelta(seconds=row.interval_seconds)
    await record_audit(db, request, "schedule.updated", "schedule", row.id, {"enabled": enabled}, principal)
    await db.commit()
    return serialize(row)


@router.delete("/{schedule_id}")
async def delete_schedule(schedule_id: str, request: Request, principal: Principal = Depends(require_permission("users:manage")), db: AsyncSession = Depends(get_db)):
    row = await db.scalar(select(Schedule).where(Schedule.id == schedule_id, Schedule.workspace_id == principal.workspace_id))
    if not row: raise HTTPException(404, "Schedule not found")
    await record_audit(db, request, "schedule.deleted", "schedule", row.id, None, principal)
    await db.delete(row); await db.commit()
    return {"deleted": True, "id": schedule_id}
