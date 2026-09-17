from __future__ import annotations
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from ..database import get_db
from ..models import Asset, Finding, OperationalEvent, Scan
from ..auth import Principal
from ..rbac import require_permission

router=APIRouter(prefix="/api/v1/dashboard",tags=["dashboard"])
SEVERITIES=("critical","high","medium","low","info")
OPEN_STATUSES=("open","triaged","assigned","in_remediation")

def scan_summary(scan:Scan)->dict:
    return {"id":scan.id,"target":scan.target,"host":scan.host,"profile":scan.profile,"status":scan.status,"created_at":scan.created_at.isoformat() if scan.created_at else None,"started_at":scan.started_at.isoformat() if scan.started_at else None,"completed_at":scan.completed_at.isoformat() if scan.completed_at else None}

@router.get("/summary")
async def summary(db:AsyncSession=Depends(get_db),principal:Principal=Depends(require_permission("scan:view"))):
    ws=principal.workspace_id
    assets=await db.scalar(select(func.count()).select_from(Asset).where(Asset.workspace_id==ws)) or 0
    scans=await db.scalar(select(func.count()).select_from(Scan).where(Scan.workspace_id==ws)) or 0
    findings=await db.scalar(select(func.count()).select_from(Finding).join(Scan).where(Scan.workspace_id==ws)) or 0
    open_findings=await db.scalar(select(func.count()).select_from(Finding).join(Scan).where(Scan.workspace_id==ws,Finding.status.in_(OPEN_STATUSES))) or 0
    severity={}
    for value in SEVERITIES:
        severity[value]=await db.scalar(select(func.count()).select_from(Finding).join(Scan).where(Scan.workspace_id==ws,Finding.severity==value,Finding.status.not_in(("closed","false_positive")))) or 0
    recent_rows=await db.scalars(select(Scan).where(Scan.workspace_id==ws).order_by(Scan.created_at.desc()).limit(8))
    recent=[scan_summary(scan) for scan in recent_rows.all()]
    cutoff=datetime.now(timezone.utc)-timedelta(days=7)
    scan_rows=await db.scalars(select(Scan).where(Scan.workspace_id==ws,Scan.created_at>=cutoff).order_by(Scan.created_at.asc()).limit(500))
    daily={ (cutoff.date()+timedelta(days=i)).isoformat():0 for i in range(8) }
    for scan in scan_rows.all():
        if scan.created_at:
            key=scan.created_at.astimezone(timezone.utc).date().isoformat(); daily[key]=daily.get(key,0)+1
    event_rows=await db.scalars(select(OperationalEvent).where(OperationalEvent.workspace_id==ws).order_by(OperationalEvent.created_at.desc()).limit(8))
    activity=[{"id":e.id,"event_type":e.event_type,"severity":e.severity,"message":e.message,"scan_id":e.scan_id,"created_at":e.created_at.isoformat() if e.created_at else None} for e in event_rows.all()]
    return {"workspace_id":ws,"assets":assets,"scans":scans,"findings":findings,"open_findings":open_findings,"critical_findings":severity["critical"],"severity":severity,"scan_volume_7d":[{"date":key,"count":daily[key]} for key in sorted(daily)],"recent_scans":recent,"activity":activity}
