from __future__ import annotations
from fastapi import APIRouter,Depends,Query
from sqlalchemy import select,desc,or_
from ..auth import Principal
from ..database import get_db
from ..models import OperationalEvent
from ..rbac import require_permission
router=APIRouter(prefix="/api/v1/operations",tags=["operations"])
@router.get("/events")
async def events(limit:int=50,severity:str|None=None,scan_id:str|None=None,event_type:str|None=None,q:str|None=None,principal:Principal=Depends(require_permission("scan:view")),db=Depends(get_db)):
 limit=max(1,min(limit,500));stmt=select(OperationalEvent).where(OperationalEvent.workspace_id==principal.workspace_id)
 if severity: stmt=stmt.where(OperationalEvent.severity==severity)
 if scan_id: stmt=stmt.where(OperationalEvent.scan_id==scan_id)
 if event_type: stmt=stmt.where(OperationalEvent.event_type==event_type)
 if q:
  term=f"%{q[:200]}%";stmt=stmt.where(or_(OperationalEvent.message.ilike(term),OperationalEvent.event_type.ilike(term)))
 rows=await db.scalars(stmt.order_by(desc(OperationalEvent.created_at)).limit(limit))
 return [{"id":e.id,"event_type":e.event_type,"severity":e.severity,"message":e.message,"scan_id":e.scan_id,"correlation_id":(e.db_metadata or {}).get("correlation_id"),"metadata":e.db_metadata,"created_at":e.created_at.isoformat() if e.created_at else None} for e in rows.all()]
