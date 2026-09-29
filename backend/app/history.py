from __future__ import annotations
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession
from .history_models import FindingHistory,ScanHistory

async def record_finding_history(db:AsyncSession,*,finding_id:str,workspace_id:str,event_type:str,snapshot:dict[str,Any],actor_id:str|None=None):
 db.add(FindingHistory(finding_id=finding_id,workspace_id=workspace_id,event_type=event_type,snapshot=snapshot,actor_id=actor_id))

async def record_scan_history(db:AsyncSession,*,scan_id:str,workspace_id:str,event_type:str,snapshot:dict[str,Any]):
 db.add(ScanHistory(scan_id=scan_id,workspace_id=workspace_id,event_type=event_type,snapshot=snapshot))
