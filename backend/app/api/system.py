from __future__ import annotations
import os,time
from datetime import datetime,timezone,timedelta
from fastapi import APIRouter,Depends
from sqlalchemy import func,select,text
from ..auth import Principal
from ..database import get_db
from ..models import Scan,Schedule
from ..queue import SCAN_GROUP,SCAN_STREAM,redis_client
from ..rbac import require_permission
router=APIRouter(prefix="/api/v1/system",tags=["system"])
HEARTBEAT_TTL=max(20,int(os.getenv("PHANTOM_WORKER_HEARTBEAT_TTL","30")))
SCHEDULER_TTL=max(30,int(os.getenv("PHANTOM_SCHEDULER_HEARTBEAT_TTL","45")))
@router.get("/status")
async def system_status(principal:Principal=Depends(require_permission("scan:view")),db=Depends(get_db)):
 now=time.time();client=redis_client();redis_ok=False;groups=[];queue_length=0;workers=[];scheduler={"status":"offline","age_seconds":None}
 try:
  started=time.perf_counter();await client.ping();redis_ms=round((time.perf_counter()-started)*1000,2);redis_ok=True
  groups=await client.xinfo_groups(SCAN_STREAM);queue_length=await client.xlen(SCAN_STREAM)
  async for key in client.scan_iter(match="phantom:worker:registration:*"):
   d=await client.hgetall(key);wid=key.rsplit(":",1)[-1];hb=await client.get(f"phantom:worker:heartbeat:{wid}")
   try: age=max(0,now-float(hb));online=age<=HEARTBEAT_TTL
   except: age=None;online=False
   workers.append({"id":wid,"status":"online" if online else "stale","heartbeat":hb,"age_seconds":round(age,1) if age is not None else None,"version":d.get("version","unknown"),"capacity":int(d.get("capacity","0") or 0),"started_at":d.get("started_at"),"last_job":d.get("last_job") or None,"last_job_at":d.get("last_job_at") or None})
  # Backward compatible heartbeat-only workers.
  known={w["id"] for w in workers}
  async for key in client.scan_iter(match="phantom:worker:heartbeat:*"):
   wid=key.rsplit(":",1)[-1]
   if wid in known: continue
   hb=await client.get(key)
   try: age=max(0,now-float(hb));online=age<=HEARTBEAT_TTL
   except: age=None;online=False
   workers.append({"id":wid,"status":"online" if online else "stale","heartbeat":hb,"age_seconds":round(age,1) if age is not None else None,"version":"legacy","capacity":None,"started_at":None,"last_job":None,"last_job_at":None})
  sh=await client.get("phantom:scheduler:heartbeat")
  if sh:
   age=max(0,now-float(sh));scheduler={"status":"online" if age<=SCHEDULER_TTL else "stale","age_seconds":round(age,1)}
 except Exception: redis_ms=None
 finally: await client.aclose()
 ws=principal.workspace_id
 started=time.perf_counter()
 try: await db.execute(text("SELECT 1"));postgres_ok=True;postgres_ms=round((time.perf_counter()-started)*1000,2)
 except Exception: postgres_ok=False;postgres_ms=None
 active=await db.scalar(select(func.count()).select_from(Scan).where(Scan.workspace_id==ws,Scan.status=="running")) or 0
 queued=await db.scalar(select(func.count()).select_from(Scan).where(Scan.workspace_id==ws,Scan.status=="queued")) or 0
 failed=await db.scalar(select(func.count()).select_from(Scan).where(Scan.workspace_id==ws,Scan.status=="failed")) or 0
 retries=await db.scalar(select(func.count()).select_from(Scan).where(Scan.workspace_id==ws,Scan.attempt>1)) or 0
 stuck_rows=(await db.scalars(select(Scan).where(Scan.workspace_id==ws,Scan.status=="running",Scan.lease_expires_at.is_not(None),Scan.lease_expires_at<datetime.now(timezone.utc)).limit(50))).all()
 recent_failed=(await db.scalars(select(Scan).where(Scan.workspace_id==ws,Scan.status=="failed").order_by(Scan.created_at.desc()).limit(20))).all()
 pending=sum(int(g.get("pending",0)) for g in groups if g.get("name")==SCAN_GROUP)
 durations=[(s.completed_at-s.started_at).total_seconds() for s in recent_failed if s.started_at and s.completed_at]
 return {"api":{"status":"healthy","version":"2.0.0"},"dependencies":{"redis":{"status":"healthy" if redis_ok else "unhealthy","latency_ms":redis_ms},"postgresql":{"status":"healthy" if postgres_ok else "unhealthy","latency_ms":postgres_ms},"scheduler":scheduler},"redis":{"stream":SCAN_STREAM,"queue_length":queue_length,"pending":pending},"workers":sorted(workers,key=lambda x:x["id"]),"scans":{"active":active,"queued":queued,"failed":failed,"retries":retries,"stuck":len(stuck_rows)},"metrics":{"failed_jobs":failed,"retry_jobs":retries,"stuck_jobs":len(stuck_rows),"avg_failed_execution_seconds":round(sum(durations)/len(durations),2) if durations else None},"failed_jobs":[{"id":s.id,"target":s.target,"attempt":s.attempt,"error":s.error,"worker_id":s.worker_id,"created_at":s.created_at.isoformat() if s.created_at else None} for s in recent_failed],"stuck_jobs":[{"id":s.id,"target":s.target,"worker_id":s.worker_id,"lease_expires_at":s.lease_expires_at.isoformat() if s.lease_expires_at else None} for s in stuck_rows]}
