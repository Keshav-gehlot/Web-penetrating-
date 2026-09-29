from __future__ import annotations
from datetime import datetime,timedelta,timezone
from sqlalchemy import delete
from .config import settings
from .database import SessionLocal
from .models import NetWatchEvent,OperationalEvent
from .api.audit import AuditEvent

async def enforce_retention()->dict[str,int]:
 now=datetime.now(timezone.utc);deleted={}
 async with SessionLocal() as db:
  for name,model,days in (
   ("audit",AuditEvent,settings.AUDIT_RETENTION_DAYS),
   ("operational",OperationalEvent,settings.OPERATIONAL_RETENTION_DAYS),
   ("net_watch",NetWatchEvent,settings.NET_WATCH_RETENTION_DAYS)):
   result=await db.execute(delete(model).where(model.created_at<now-timedelta(days=days)))
   deleted[name]=result.rowcount or 0
  await db.commit()
 return deleted
