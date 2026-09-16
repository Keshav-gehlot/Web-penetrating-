from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..realtime import bus

router = APIRouter(tags=["realtime"])


@router.websocket("/ws/scans/{scan_id}")
async def scan_events(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    queue = await bus.subscribe(scan_id)
    try:
        await websocket.send_json({"event": "connected", "scan_id": scan_id})
        while True:
            event = await queue.get()
            await websocket.send_json(event)
            if event.get("event") in {"scan.completed", "scan.failed"}:
                break
    except WebSocketDisconnect:
        pass
    finally:
        await bus.unsubscribe(scan_id, queue)
