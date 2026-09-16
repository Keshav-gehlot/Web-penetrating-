from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from ..main import validate_target
from ..scanners.modules import MODULES, PROFILES
from ..scanners.runner import run_profile

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    profile: str = Field(default="standard", pattern="^(quick|standard|deep)$")

SCANS: dict[str, dict] = {}

async def execute_scan(scan_id: str):
    scan = SCANS[scan_id]
    scan["status"] = "running"
    scan["started_at"] = datetime.now(timezone.utc).isoformat()
    try:
        scan["results"] = await run_profile(scan["profile"], scan["target"])
        scan["findings"] = [f for result in scan["results"] for f in result.get("findings", [])]
        scan["status"] = "completed"
    except Exception as exc:
        scan["status"] = "failed"
        scan["error"] = str(exc)
    scan["completed_at"] = datetime.now(timezone.utc).isoformat()

@router.get("/modules")
async def list_modules():
    return {
        "count": len(MODULES),
        "modules": [{"id": name, "status": "implemented"} for name in MODULES],
        "profiles": {k: list(v) for k, v in PROFILES.items()},
    }

@router.post("")
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    target = validate_target(request.target)
    scan_id = str(uuid4())
    SCANS[scan_id] = {
        "id": scan_id, "target": target["target"], "host": target["host"],
        "profile": request.profile, "modules": list(PROFILES[request.profile]),
        "status": "queued", "created_at": datetime.now(timezone.utc).isoformat(),
        "results": [], "findings": []
    }
    background_tasks.add_task(execute_scan, scan_id)
    return SCANS[scan_id]

@router.post("/{scan_id}/run")
async def run_scan(scan_id: str):
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    if SCANS[scan_id]["status"] == "running":
        raise HTTPException(status_code=409, detail="Scan is already running")
    await execute_scan(scan_id)
    return SCANS[scan_id]

@router.get("")
async def list_scans():
    return list(SCANS.values())

@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
