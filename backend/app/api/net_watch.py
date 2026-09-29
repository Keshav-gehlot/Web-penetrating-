from __future__ import annotations
import csv, io, json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import Principal
from ..config import settings
from ..database import get_db
from ..models import Finding, NetWatchBaseline, NetWatchEvent, Scan
from ..rbac import require_permission

router=APIRouter(prefix="/api/v1/net-watch",tags=["net-watch"])

def serialize(e):
    return {"id":e.id,"kind":e.kind,"severity":e.severity,"summary":e.summary,"explanation":e.explanation,"data":e.data,"baseline":e.baseline,"finding_id":e.finding_id,"acknowledged_at":e.acknowledged_at.isoformat() if e.acknowledged_at else None,"acknowledged_by":e.acknowledged_by,"created_at":e.created_at.isoformat() if e.created_at else None}

@router.get("/timeline")
async def timeline(kind:str|None=None,limit:int=100,principal:Principal=Depends(require_permission("scan:view")),db:AsyncSession=Depends(get_db)):
    q=select(NetWatchEvent).where(NetWatchEvent.workspace_id==principal.workspace_id)
    if kind:q=q.where(NetWatchEvent.kind==kind)
    rows=(await db.scalars(q.order_by(NetWatchEvent.created_at.desc()).limit(min(max(limit,1),1000)))).all()
    return [serialize(x) for x in rows]

@router.get("/baselines")
async def baselines(principal:Principal=Depends(require_permission("scan:view")),db:AsyncSession=Depends(get_db)):
    rows=(await db.scalars(select(NetWatchBaseline).where(NetWatchBaseline.workspace_id==principal.workspace_id))).all()
    return [{"metric":x.metric,"value":x.value,"sample_count":x.sample_count,"updated_at":x.updated_at.isoformat() if x.updated_at else None} for x in rows]

@router.get("/status")
async def status(principal:Principal=Depends(require_permission("scan:view")),db:AsyncSession=Depends(get_db)):
    latest=await db.scalar(select(NetWatchEvent).where(NetWatchEvent.workspace_id==principal.workspace_id).order_by(NetWatchEvent.created_at.desc()).limit(1))
    return {"enabled":settings.NET_WATCH_ENABLED,"last_event_at":latest.created_at.isoformat() if latest and latest.created_at else None,"sensor":(latest.data or {}).get("sensor") if latest else None,"retention_days":settings.NET_WATCH_RETENTION_DAYS}

class Ack(BaseModel):acknowledged:bool=True
@router.patch("/events/{event_id}/acknowledge")
async def acknowledge(event_id:str,body:Ack,principal:Principal=Depends(require_permission("finding:edit")),db:AsyncSession=Depends(get_db)):
    event=await db.scalar(select(NetWatchEvent).where(NetWatchEvent.id==event_id,NetWatchEvent.workspace_id==principal.workspace_id))
    if not event:raise HTTPException(404,"Net-Watch event not found")
    event.acknowledged_at=datetime.now(timezone.utc) if body.acknowledged else None;event.acknowledged_by=principal.actor if body.acknowledged else None
    await db.commit();await db.refresh(event);return serialize(event)

class Link(BaseModel):finding_id:str=Field(min_length=1,max_length=36)
@router.patch("/events/{event_id}/finding")
async def link_finding(event_id:str,body:Link,principal:Principal=Depends(require_permission("finding:edit")),db:AsyncSession=Depends(get_db)):
    event=await db.scalar(select(NetWatchEvent).where(NetWatchEvent.id==event_id,NetWatchEvent.workspace_id==principal.workspace_id))
    if not event:raise HTTPException(404,"Net-Watch event not found")
    finding=await db.scalar(select(Finding).join(Scan).where(Finding.id==body.finding_id,Scan.workspace_id==principal.workspace_id))
    if not finding:raise HTTPException(404,"Finding not found")
    event.finding_id=finding.id;await db.commit();await db.refresh(event);return serialize(event)

@router.get("/correlations")
async def correlations(principal:Principal=Depends(require_permission("finding:view")),db:AsyncSession=Depends(get_db)):
    rows=(await db.scalars(select(NetWatchEvent).where(NetWatchEvent.workspace_id==principal.workspace_id,NetWatchEvent.finding_id.is_not(None)).order_by(NetWatchEvent.created_at.desc()).limit(500))).all()
    return [serialize(x) for x in rows]

async def _rows(db,workspace_id):
    return (await db.scalars(select(NetWatchEvent).where(NetWatchEvent.workspace_id==workspace_id).order_by(NetWatchEvent.created_at.desc()).limit(10000))).all()

@router.get("/export.csv")
async def export_csv(principal:Principal=Depends(require_permission("report:export")),db:AsyncSession=Depends(get_db)):
    rows=await _rows(db,principal.workspace_id);out=io.StringIO();w=csv.writer(out);w.writerow(["id","created_at","kind","severity","summary","explanation","finding_id","acknowledged_at","acknowledged_by"])
    for e in rows:w.writerow([e.id,e.created_at.isoformat() if e.created_at else "",e.kind,e.severity,e.summary,e.explanation,e.finding_id or "",e.acknowledged_at.isoformat() if e.acknowledged_at else "",e.acknowledged_by or ""])
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=net-watch.csv"})

@router.get("/export.json")
async def export_json(principal:Principal=Depends(require_permission("report:export")),db:AsyncSession=Depends(get_db)):
    rows=await _rows(db,principal.workspace_id);payload=json.dumps([serialize(x) for x in rows],default=str)
    return StreamingResponse(iter([payload]),media_type="application/json",headers={"Content-Disposition":"attachment; filename=net-watch.json"})
