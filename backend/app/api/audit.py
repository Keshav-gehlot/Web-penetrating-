from __future__ import annotations
import csv,io
from datetime import datetime
from typing import Any
from uuid import uuid4
from fastapi import APIRouter,Depends,Request
from fastapi.responses import StreamingResponse
from sqlalchemy import DateTime,JSON,String,func,select,or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped,mapped_column
from ..auth import Principal
from ..database import Base,get_db
from ..rbac import require_permission
class AuditEvent(Base):
 __tablename__="audit_events"
 id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid4()))
 workspace_id:Mapped[str|None]=mapped_column(String(36),nullable=True,index=True)
 actor:Mapped[str]=mapped_column(String(255),default="unknown",index=True)
 action:Mapped[str]=mapped_column(String(100),index=True)
 resource_type:Mapped[str]=mapped_column(String(100),index=True)
 resource_id:Mapped[str|None]=mapped_column(String(255),nullable=True,index=True)
 metadata_json:Mapped[dict[str,Any]]=mapped_column(JSON,default=dict)
 created_at:Mapped[Any]=mapped_column(DateTime(timezone=True),server_default=func.now(),index=True)
router=APIRouter(prefix="/api/v1/audit",tags=["audit"])
async def record_audit(db:AsyncSession,request:Request|None,action:str,resource_type:str,resource_id:str|None=None,metadata:dict[str,Any]|None=None,principal:Principal|None=None,workspace_id:str|None=None,actor:str|None=None):
 meta=dict(metadata or {})
 if request:
  meta.setdefault("request_id",getattr(request.state,"request_id",None));meta.setdefault("ip",request.client.host if request.client else None)
 e=AuditEvent(workspace_id=principal.workspace_id if principal else workspace_id,actor=principal.actor if principal else(actor or "system"),action=action,resource_type=resource_type,resource_id=resource_id,metadata_json=meta);db.add(e);await db.flush();return e
def query(ws,actor=None,action=None,resource_type=None,resource_id=None,q=None,date_from=None,date_to=None):
 s=select(AuditEvent).where(AuditEvent.workspace_id==ws)
 if actor:s=s.where(AuditEvent.actor.ilike(f"%{actor[:255]}%"))
 if action:s=s.where(AuditEvent.action==action)
 if resource_type:s=s.where(AuditEvent.resource_type==resource_type)
 if resource_id:s=s.where(AuditEvent.resource_id==resource_id)
 if q:
  t=f"%{q[:200]}%";s=s.where(or_(AuditEvent.actor.ilike(t),AuditEvent.action.ilike(t),AuditEvent.resource_type.ilike(t),AuditEvent.resource_id.ilike(t)))
 if date_from:s=s.where(AuditEvent.created_at>=date_from)
 if date_to:s=s.where(AuditEvent.created_at<=date_to)
 return s
@router.get("")
async def list_audit(actor:str|None=None,action:str|None=None,resource_type:str|None=None,resource_id:str|None=None,q:str|None=None,date_from:datetime|None=None,date_to:datetime|None=None,limit:int=100,offset:int=0,principal:Principal=Depends(require_permission("audit:view")),db:AsyncSession=Depends(get_db)):
 rows=await db.scalars(query(principal.workspace_id,actor,action,resource_type,resource_id,q,date_from,date_to).order_by(AuditEvent.created_at.desc()).offset(max(0,offset)).limit(max(1,min(limit,500))))
 return [{"id":e.id,"actor":e.actor,"action":e.action,"resource_type":e.resource_type,"resource_id":e.resource_id,"metadata":e.metadata_json,"created_at":e.created_at.isoformat() if e.created_at else None} for e in rows.all()]
@router.get("/export.csv")
async def export_audit(actor:str|None=None,action:str|None=None,resource_type:str|None=None,resource_id:str|None=None,q:str|None=None,date_from:datetime|None=None,date_to:datetime|None=None,principal:Principal=Depends(require_permission("audit:view")),db:AsyncSession=Depends(get_db)):
 rows=(await db.scalars(query(principal.workspace_id,actor,action,resource_type,resource_id,q,date_from,date_to).order_by(AuditEvent.created_at.desc()).limit(10000))).all();buf=io.StringIO();w=csv.writer(buf);w.writerow(["timestamp","actor","action","resource_type","resource_id","metadata"])
 for e in rows:w.writerow([e.created_at.isoformat() if e.created_at else "",e.actor,e.action,e.resource_type,e.resource_id or "",str(e.metadata_json or {})])
 data=buf.getvalue().encode();return StreamingResponse(iter([data]),media_type="text/csv",headers={"Content-Disposition":'attachment; filename="phantom-audit.csv"'})
