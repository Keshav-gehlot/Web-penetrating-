from __future__ import annotations
import json
from fastapi import APIRouter, Depends, HTTPException, WebSocket
from sqlalchemy import select
from ..auth import Principal, consume_ws_ticket, issue_ws_ticket
from ..database import SessionLocal
from ..models import Scan
from ..rbac import require_permission
from ..realtime import bus
router=APIRouter(tags=["realtime"])
@router.post("/api/v1/events/ws-ticket")
async def websocket_ticket(scan_id:str,principal:Principal=Depends(require_permission("scan:view"))):
    async with SessionLocal() as db:
        scan=await db.scalar(select(Scan).where(Scan.id==scan_id,Scan.workspace_id==principal.workspace_id))
    if not scan:raise HTTPException(404,"Scan not found")
    return {"ticket":await issue_ws_ticket(principal,scan_id)}
@router.websocket("/ws/scans/{scan_id}")
async def scan_events(websocket:WebSocket,scan_id:str):
    ticket=websocket.query_params.get("ticket")
    if not ticket:
        await websocket.close(code=4401);return
    try:principal=await consume_ws_ticket(ticket,scan_id)
    except Exception:
        await websocket.close(code=4401);return
    async with SessionLocal() as db:
        scan=await db.scalar(select(Scan).where(Scan.id==scan_id,Scan.workspace_id==principal.workspace_id))
    if not scan:
        await websocket.close(code=4404);return
    client,pubsub=await bus.subscribe(scan_id);await websocket.accept()
    try:
        await websocket.send_json({"event":"connected","scan_id":scan_id})
        while True:
            message=await pubsub.get_message(ignore_subscribe_messages=True,timeout=30)
            if message is None:continue
            try:event=json.loads(message["data"])
            except (TypeError,json.JSONDecodeError):continue
            await websocket.send_json(event)
            if event.get("event") in {"scan.completed","scan.failed","scan.cancelled"}:break
    finally:
        await pubsub.unsubscribe(f"phantom:scan:events:{scan_id}");await pubsub.close();await client.aclose()
