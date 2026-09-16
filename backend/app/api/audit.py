from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from fastapi import APIRouter, Depends, Request
from sqlalchemy import DateTime, JSON, String, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base, get_db
from ..rbac import require_permission

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    actor: Mapped[str] = mapped_column(String(255), default="unknown")
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str] = mapped_column(String(100), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])

async def record_audit(db: AsyncSession, request: Request, action: str, resource_type: str, resource_id: str | None = None, metadata: dict[str, Any] | None = None):
    event = AuditEvent(actor=request.headers.get("X-PHANTOM-Actor", "unknown"), action=action, resource_type=resource_type, resource_id=resource_id, metadata_json=metadata or {})
    db.add(event)
    await db.flush()
    return event

@router.get("", dependencies=[Depends(require_permission("audit:view"))])
async def list_audit(db: AsyncSession = Depends(get_db), limit: int = 100):
    limit = max(1, min(limit, 250))
    rows = await db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit))
    return [{"id": e.id, "actor": e.actor, "action": e.action, "resource_type": e.resource_type, "resource_id": e.resource_id, "metadata": e.metadata_json, "created_at": e.created_at.isoformat() if e.created_at else None} for e in rows.all()]
