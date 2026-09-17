from __future__ import annotations
import os,time
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from ..auth import Principal
from ..database import get_db
from ..models import Scan
from ..queue import SCAN_GROUP, SCAN_STREAM, redis_client
from ..rbac import require_permission
router=APIRouter(prefix="/api/v1/system",tags=["system"])
HEARTBEAT_TTL=max(20,int(os.getenv("PHANTOM_WORKER_HEARTBEAT_TTL","30")))
@router.get("/status")
async def system_status(principal:Principal=Depends(require_permission("scan:view")),db=Depends(get_db)):
    client=redis_client();now=time.time()
    try:
        groups=await client.xinfo_groups(SCAN_STREAM);queue_length=await client.xlen(SCAN_STREAM);workers=[]
        async for key in client.scan_iter(match="phantom:worker:heartbeat:*"):
            value=await client.get(key)
            try: heartbeat=float(value);age=max(0,now-heartbeat);online=age<=HEARTBEAT_TTL
            except (TypeError,ValueError): heartbeat=0;age=None;online=False
            workers.append({"id":key.rsplit(":",1)[-1],"status":"online" if online else "stale","heartbeat":value,"age_seconds":round(age,1) if age is not None else None})
        workers.sort(key=lambda item:item["id"])
    except Exception:
        groups=[];queue_length=0;workers=[]
    finally: await client.aclose()
    ws=principal.workspace_id
    active=await db.scalar(select(func.count()).select_from(Scan).where(Scan.workspace_id==ws,Scan.status=="running")) or 0
    queued=await db.scalar(select(func.count()).select_from(Scan).where(Scan.workspace_id==ws,Scan.status=="queued")) or 0
    pending=sum(int(group.get("pending",0)) for group in groups if group.get("name")==SCAN_GROUP)
    return {"redis":{"stream":SCAN_STREAM,"queue_length":queue_length,"pending":pending},"workers":workers,"scans":{"active":active,"queued":queued}}
