from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import Principal
from ..database import SessionLocal, get_db
from ..main import validate_target
from ..models import Asset, Finding, Scan
from ..queue import enqueue_scan
from ..rbac import require_permission
from ..realtime import bus
from ..scanners.runner import MODULES, PROFILES, run_module
from .findings import fingerprint_for
router=APIRouter(prefix="/api/v1/scans",tags=["scans"])
class ScanRequest(BaseModel):target:str=Field(min_length=1,max_length=2048);profile:str=Field(default="standard",pattern="^(quick|standard|deep|trust)$")
def serialize_scan(scan):return {"id":scan.id,"target":scan.target,"host":scan.host,"profile":scan.profile,"modules":scan.modules,"status":scan.status,"created_at":scan.created_at.isoformat() if scan.created_at else None,"started_at":scan.started_at.isoformat() if scan.started_at else None,"completed_at":scan.completed_at.isoformat() if scan.completed_at else None,"error":scan.error}
def severity_rank(v):return {"info":0,"low":1,"medium":2,"high":3,"critical":4}.get(v.lower(),0)
def serialize_finding(f):return {"id":f.id,"module":f.module,"title":f.title,"severity":f.severity,"status":f.status,"fingerprint":f.fingerprint,"cve":f.cve,"cwe":f.cwe,"cvss":f.cvss,"assignee":f.assignee,"description":f.description,"remediation":f.remediation,"evidence":f.evidence,"confidence":f.confidence}
async def execute_scan(scan_id):
 async with SessionLocal() as db:
  scan=await db.get(Scan,scan_id)
  if not scan:return
  scan.status="running";scan.started_at=datetime.now(timezone.utc);await db.commit();await bus.publish(scan_id,{"event":"scan.started","scan_id":scan_id})
  try:
   total=len(scan.modules)
   for index,module_name in enumerate(scan.modules,1):
    state=await db.get(Scan,scan_id)
    if not state or state.status=="cancelled":
     await bus.publish(scan_id,{"event":"scan.cancelled","scan_id":scan_id});return
    await bus.publish(scan_id,{"event":"module.started","scan_id":scan_id,"module":module_name,"index":index,"total":total})
    result=await run_module(module_name,scan.target);seen=set()
    for item in result.get("findings",[]):
     state=await db.get(Scan,scan_id)
     if not state or state.status=="cancelled":
      await bus.publish(scan_id,{"event":"scan.cancelled","scan_id":scan_id});return
     fp=fingerprint_for(scan,item)
     if fp in seen:continue
     seen.add(fp);existing=await db.scalar(select(Finding).where(Finding.scan_id==scan.id,Finding.fingerprint==fp))
     if existing:existing.last_seen=datetime.now(timezone.utc);continue
     finding=Finding(scan_id=scan.id,module=item.get("module",module_name),title=item.get("title","Untitled finding"),severity=item.get("severity","info"),status="open",fingerprint=fp,cve=item.get("cve"),cwe=item.get("cwe"),cvss=item.get("cvss"),description=item.get("description",""),remediation=item.get("remediation",""),evidence=item.get("evidence",{}),confidence=float(item.get("confidence",1.0)))
     db.add(finding);await db.flush();await bus.publish(scan_id,{"event":"finding.created","scan_id":scan_id,"finding":serialize_finding(finding)})
    await db.commit();await bus.publish(scan_id,{"event":"module.completed","scan_id":scan_id,"module":module_name,"index":index,"total":total})
   scan.status="completed"
  except Exception as exc:
   scan.status="failed";scan.error=str(exc);await db.commit();await bus.publish(scan_id,{"event":"scan.failed","scan_id":scan_id,"error":str(exc)});return
  scan.completed_at=datetime.now(timezone.utc);await db.commit();await bus.publish(scan_id,{"event":"scan.completed","scan_id":scan_id})
@router.get("/modules")
async def list_modules(principal:Principal=Depends(require_permission("scan:view"))):return {"count":len(MODULES),"modules":[{"id":n,"status":"implemented"} for n in MODULES],"profiles":{k:list(v) for k,v in PROFILES.items()}}
@router.post("")
async def create_scan(request:ScanRequest,principal:Principal=Depends(require_permission("scan:create")),db:AsyncSession=Depends(get_db)):
 target=validate_target(request.target);asset=await db.scalar(select(Asset).where(Asset.workspace_id==principal.workspace_id,Asset.host==target["host"]))
 if not asset:asset=Asset(host=target["host"],target=target["target"],workspace_id=principal.workspace_id);db.add(asset);await db.flush()
 scan=Scan(id=str(uuid4()),target=target["target"],host=target["host"],profile=request.profile,modules=list(PROFILES[request.profile]),status="queued",asset_id=asset.id,workspace_id=principal.workspace_id);db.add(scan);await db.commit();await db.refresh(scan)
 await enqueue_scan(scan.id);await bus.publish(scan.id,{"event":"scan.created","scan_id":scan.id});return serialize_scan(scan)
@router.post("/{scan_id}/run")
async def run_scan(scan_id:str,principal:Principal=Depends(require_permission("scan:create")),db:AsyncSession=Depends(get_db)):
 scan=await db.scalar(select(Scan).where(Scan.id==scan_id,Scan.workspace_id==principal.workspace_id))
 if not scan:raise HTTPException(404,"Scan not found")
 if scan.status=="running":raise HTTPException(409,"Scan is already running")
 if scan.status=="cancelled":raise HTTPException(409,"Cancelled scans cannot be restarted")
 scan.status="queued";scan.error=None;await db.commit();await enqueue_scan(scan_id);return serialize_scan(scan)
@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id:str,principal:Principal=Depends(require_permission("scan:cancel")),db:AsyncSession=Depends(get_db)):
 scan=await db.scalar(select(Scan).where(Scan.id==scan_id,Scan.workspace_id==principal.workspace_id))
 if not scan:raise HTTPException(404,"Scan not found")
 if scan.status in {"completed","failed","cancelled"}:return serialize_scan(scan)
 scan.status="cancelled";scan.completed_at=datetime.now(timezone.utc);scan.error="Cancelled by authorized user";await db.commit();await bus.publish(scan_id,{"event":"scan.cancelled","scan_id":scan_id});return serialize_scan(scan)
@router.get("")
async def list_scans(principal:Principal=Depends(require_permission("scan:view")),db:AsyncSession=Depends(get_db)):
 rows=await db.scalars(select(Scan).where(Scan.workspace_id==principal.workspace_id).order_by(Scan.created_at.desc()).limit(100));return [serialize_scan(s) for s in rows.all()]
@router.get("/{scan_id}/delta")
async def scan_delta(scan_id:str,principal:Principal=Depends(require_permission("scan:view")),db:AsyncSession=Depends(get_db)):
 current=await db.scalar(select(Scan).where(Scan.id==scan_id,Scan.workspace_id==principal.workspace_id))
 if not current:raise HTTPException(404,"Scan not found")
 previous=await db.scalar(select(Scan).where(Scan.asset_id==current.asset_id,Scan.workspace_id==principal.workspace_id,Scan.id!=scan_id,Scan.status=="completed").order_by(Scan.completed_at.desc()))
 rows=await db.scalars(select(Finding).where(Finding.scan_id==scan_id));cm={f.fingerprint:f for f in rows.all()}
 if not previous:return {"scan_id":scan_id,"previous_scan_id":None,"new":[serialize_finding(f) for f in cm.values()],"resolved":[],"persistent":[],"regressions":[]}
 rows=await db.scalars(select(Finding).where(Finding.scan_id==previous.id));pm={f.fingerprint:f for f in rows.all()}
 return {"scan_id":scan_id,"previous_scan_id":previous.id,"new":[serialize_finding(cm[k]) for k in cm.keys()-pm.keys()],"resolved":[serialize_finding(pm[k]) for k in pm.keys()-cm.keys()],"persistent":[serialize_finding(cm[k]) for k in cm.keys()&pm.keys()],"regressions":[serialize_finding(cm[k]) for k in cm.keys()&pm.keys() if severity_rank(cm[k].severity)>severity_rank(pm[k].severity)]}
@router.get("/{scan_id}")
async def get_scan(scan_id:str,principal:Principal=Depends(require_permission("scan:view")),db:AsyncSession=Depends(get_db)):
 scan=await db.scalar(select(Scan).where(Scan.id==scan_id,Scan.workspace_id==principal.workspace_id))
 if not scan:raise HTTPException(404,"Scan not found")
 rows=await db.scalars(select(Finding).where(Finding.scan_id==scan_id).order_by(Finding.created_at.desc()));payload=serialize_scan(scan);payload["findings"]=[serialize_finding(f) for f in rows.all()];return payload
