from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from ..auth import Principal
from ..database import get_db
from ..models import Scan
from ..queue import SCAN_GROUP, SCAN_STREAM, redis_client
from ..rbac import require_permission
router=APIRouter(prefix="/api/v1/system",tags=["system"])
@router.get("/status")
async def system_status(principal:Principal=Depends(require_permission("scan:view")),db=Depends(get_db)):
    client=redis_client()
    try:
        groups=await client.xinfo_groups(SCAN_STREAM)
        queue_length=await client.xlen(SCAN_STREAM)
        workers=[]
        keys=[]
        async for key in client.scan_iter(match="phantom:worker:heartbeat:*"):
            keys.append(key)
        for key in keys:
            value=await client.get(key)
            workers.append({"id":key.rsplit(":",1)[-1],"status":"online","heartbeat":value})
    except Exception:
        groups=[];queue_length=0;workers=[]
    finally:
        await client.aclose()
    ws=principal.workspace_id
    active=await db.scalar(select(func.count()).select_from(Scan).where(Scan.workspace_id==ws,Scan.status=="running")) or 0
    queued=await db.scalar(select(func.count()).select_from(Scan).where(Scan.workspace_id==ws,Scan.status=="queued")) or 0
    pending=sum(int(group.get("pending",0)) for group in groups if group.get("name")==SCAN_GROUP)
    return {"redis":{"stream":SCAN_STREAM,"queue_length":queue_length,"pending":pending},"workers":workers,"scans":{"active":active,"queued":queued}}
