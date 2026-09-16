from __future__ import annotations
from fastapi import APIRouter, Depends, WebSocket, HTTPException
from ..auth import Principal, current_principal, issue_token, principal_from_token
from ..database import SessionLocal
from ..models import Scan
from ..rbac import require_permission
from ..realtime import bus
from sqlalchemy import select
router=APIRouter(tags=["realtime"])
@router.post("/api/v1/events/ws-ticket")
async def websocket_ticket(scan_id:str,principal:Principal=Depends(require_permission("scan:view"))):
    async with SessionLocal() as db:
        scan=await db.scalar(select(Scan).where(Scan.id==scan_id,Scan.workspace_id==principal.workspace_id))
    if not scan: raise HTTPException(404,"Scan not found")
    return {"ticket":issue_token(principal.actor,principal.role,principal.workspace_id,principal.user_id,hours=1)}
@router.websocket("/ws/scans/{scan_id}")
async def scan_events(websocket:WebSocket,scan_id:str):
    token=websocket.cookies.get("phantom_access_token") or websocket.query_params.get("ticket")
    if not token:
        await websocket.close(code=4401);return
    try: principal=principal_from_token(token)
    except Exception:
        await websocket.close(code=4401);return
    async with SessionLocal() as db:
        scan=await db.scalar(select(Scan).where(Scan.id==scan_id,Scan.workspace_id==principal.workspace_id))
    if not scan:
        await websocket.close(code=4404);return
    await websocket.accept();queue=await bus.subscribe(scan_id)
    try:
        await websocket.send_json({"event":"connected","scan_id":scan_id})
        while True:
            event=await queue.get();await websocket.send_json(event)
            if event.get("event") in {"scan.completed","scan.failed"}:break
    finally:await bus.unsubscribe(scan_id,queue)
