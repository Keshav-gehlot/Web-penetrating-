from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from uuid import uuid4
from datetime import datetime, timezone

from ..main import validate_target
from ..scanners import scan_headers, scan_dns, scan_tls

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    profile: str = Field(default="standard", pattern="^(quick|standard|deep)$")

SCANS: dict[str, dict] = {}

@router.post("")
async def create_scan(request: ScanRequest):
    target = validate_target(request.target)
    scan_id = str(uuid4())
    SCANS[scan_id] = {
        "id": scan_id, "target": target["target"], "profile": request.profile,
        "status": "queued", "created_at": datetime.now(timezone.utc).isoformat(), "results": []
    }
    return SCANS[scan_id]

@router.post("/{scan_id}/run")
async def run_scan(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan["status"] = "running"
    target = scan["target"]
    results = []
    # Safe baseline modules: no exploit payloads or destructive actions.
    for module in (scan_dns, scan_headers, scan_tls):
        try:
            results.append(await module(target))
        except Exception as exc:
            results.append({"module": module.__name__, "error": str(exc), "findings": []})
    scan["results"] = results
    scan["status"] = "completed"
    scan["completed_at"] = datetime.now(timezone.utc).isoformat()
    return scan

@router.get("")
async def list_scans():
    return list(SCANS.values())

@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
