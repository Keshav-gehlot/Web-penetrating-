from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy import select, desc
from ..auth import Principal
from ..database import get_db
from ..models import OperationalEvent
from ..rbac import require_permission
router=APIRouter(prefix="/api/v1/operations",tags=["operations"])
@router.get("/events")
async def events(limit:int=50,principal:Principal=Depends(require_permission("scan:view")),db=Depends(get_db)):
    limit=max(1,min(limit,200))
    rows=await db.scalars(select(OperationalEvent).where(OperationalEvent.workspace_id==principal.workspace_id).order_by(desc(OperationalEvent.created_at)).limit(limit))
    return [{"id":e.id,"event_type":e.event_type,"severity":e.severity,"message":e.message,"scan_id":e.scan_id,"metadata":e.db_metadata,"created_at":e.created_at.isoformat() if e.created_at else None} for e in rows.all()]
