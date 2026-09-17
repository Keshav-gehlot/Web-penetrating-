from __future__ import annotations

from fastapi import APIRouter, Depends

from ..auth import Principal
from ..network_anomaly import engine
from ..network_monitor import monitor
from ..rbac import require_permission

router = APIRouter(prefix="/api/v1/network", tags=["network"])


@router.get("/anomaly")
async def network_anomaly(principal: Principal = Depends(require_permission("scan:view"))):
    del principal
    snapshot = monitor.snapshot(include_listening=True)
    result = engine.observe(snapshot)
    return {"timestamp": snapshot["timestamp"], "hostname": snapshot["hostname"], "anomaly": result}
