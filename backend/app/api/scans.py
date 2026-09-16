from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import SessionLocal, get_db
from ..main import validate_target
from ..models import Asset, Finding, Scan
from ..scanners.modules import MODULES, PROFILES
from ..scanners.runner import run_profile

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    profile: str = Field(default="standard", pattern="^(quick|standard|deep)$")

def serialize_scan(scan: Scan) -> dict:
    return {"id": scan.id, "target": scan.target, "host": scan.host, "profile": scan.profile,
            "modules": scan.modules, "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "error": scan.error}

async def execute_scan(scan_id: str):
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan: return
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()
        try:
            results = await run_profile(scan.profile, scan.target)
            for result in results:
                for item in result.get("findings", []):
                    db.add(Finding(scan_id=scan.id, module=item.get("module", result.get("module", "unknown")),
                                   title=item.get("title", "Untitled finding"), severity=item.get("severity", "info"),
                                   description=item.get("description", ""), remediation=item.get("remediation", ""),
                                   evidence=item.get("evidence", {}), confidence=float(item.get("confidence", 1.0))))
            scan.status = "completed"
        except Exception as exc:
            scan.status = "failed"
            scan.error = str(exc)
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()

@router.get("/modules")
async def list_modules():
    return {"count": len(MODULES), "modules": [{"id": n, "status": "implemented"} for n in MODULES],
            "profiles": {k: list(v) for k, v in PROFILES.items()}}

@router.post("")
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks,
                      db: AsyncSession = Depends(get_db)):
    target = validate_target(request.target)
    asset = await db.scalar(select(Asset).where(Asset.host == target["host"]))
    if not asset:
        asset = Asset(host=target["host"], target=target["target"])
        db.add(asset)
        await db.flush()
    scan = Scan(id=str(uuid4()), target=target["target"], host=target["host"], profile=request.profile,
                modules=list(PROFILES[request.profile]), status="queued", asset_id=asset.id)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    background_tasks.add_task(execute_scan, scan.id)
    return serialize_scan(scan)

@router.post("/{scan_id}/run")
async def run_scan(scan_id: str):
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan: raise HTTPException(status_code=404, detail="Scan not found")
        if scan.status == "running": raise HTTPException(status_code=409, detail="Scan is already running")
    await execute_scan(scan_id)
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        return serialize_scan(scan)

@router.get("")
async def list_scans(db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(100))
    return [serialize_scan(scan) for scan in rows.all()]

@router.get("/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan: raise HTTPException(status_code=404, detail="Scan not found")
    rows = await db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at.desc()))
    payload = serialize_scan(scan)
    payload["findings"] = [{"id": f.id, "module": f.module, "title": f.title, "severity": f.severity,
                            "description": f.description, "remediation": f.remediation,
                            "evidence": f.evidence, "confidence": f.confidence} for f in rows.all()]
    return payload
