from __future__ import annotations
from typing import Any
from uuid import uuid4
from .database import SessionLocal
from .models import OperationalEvent
async def record_operational_event(event_type:str,message:str,severity:str="info",workspace_id:str|None=None,scan_id:str|None=None,metadata:dict[str,Any]|None=None)->None:
    async with SessionLocal() as db:
        db.add(OperationalEvent(id=str(uuid4()),event_type=event_type,message=message,severity=severity,workspace_id=workspace_id,scan_id=scan_id,metadata=metadata or {}))
        await db.commit()
