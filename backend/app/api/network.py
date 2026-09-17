from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ..auth import Principal
from ..network_monitor import monitor
from ..rbac import require_permission

router = APIRouter(prefix="/api/v1/network", tags=["network"])


@router.get("/snapshot")
async def network_snapshot(
    include_listening: bool = Query(True),
    principal: Principal = Depends(require_permission("scan:view")),
):
    del principal
    return monitor.snapshot(include_listening=include_listening)


@router.get("/connections")
async def network_connections(
    principal: Principal = Depends(require_permission("scan:view")),
):
    del principal
    snapshot = monitor.snapshot(include_listening=True)
    return {
        "timestamp": snapshot["timestamp"],
        "count": snapshot["connection_count"],
        "new_count": snapshot["new_connection_count"],
        "connections": snapshot["connections"],
    }


@router.get("/interfaces")
async def network_interfaces(
    principal: Principal = Depends(require_permission("scan:view")),
):
    del principal
    snapshot = monitor.snapshot(include_listening=False)
    return {
        "timestamp": snapshot["timestamp"],
        "io": snapshot["network_io"],
        "vpn_interfaces": snapshot["vpn_interfaces"],
    }
