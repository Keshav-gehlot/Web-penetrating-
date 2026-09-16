from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from ..database import get_db
from ..models import Asset, Finding, Scan
from ..auth import Principal, current_principal

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])

@router.get("/summary")
async def summary(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)):
    assets = await db.scalar(select(func.count()).select_from(Asset)) or 0
    scans = await db.scalar(select(func.count()).select_from(Scan)) or 0
    findings = await db.scalar(select(func.count()).select_from(Finding)) or 0
    open_findings = await db.scalar(select(func.count()).select_from(Finding).where(Finding.status.in_(["open", "triaged", "assigned", "in_remediation"]))) or 0
    critical = await db.scalar(select(func.count()).select_from(Finding).where(Finding.severity == "critical", Finding.status.not_in(["closed", "false_positive"]))) or 0
    return {"workspace_id": principal.workspace_id, "assets": assets, "scans": scans, "findings": findings, "open_findings": open_findings, "critical_findings": critical}
