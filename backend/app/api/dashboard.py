from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from ..database import get_db
from ..models import Asset, Finding, Scan
from ..auth import Principal
from ..rbac import require_permission
router=APIRouter(prefix="/api/v1/dashboard",tags=["dashboard"])
@router.get("/summary")
async def summary(db:AsyncSession=Depends(get_db),principal:Principal=Depends(require_permission("scan:view"))):
    ws=principal.workspace_id
    assets=await db.scalar(select(func.count()).select_from(Asset).where(Asset.workspace_id==ws)) or 0
    scans=await db.scalar(select(func.count()).select_from(Scan).where(Scan.workspace_id==ws)) or 0
    findings=await db.scalar(select(func.count()).select_from(Finding).join(Scan).where(Scan.workspace_id==ws)) or 0
    open_findings=await db.scalar(select(func.count()).select_from(Finding).join(Scan).where(Scan.workspace_id==ws,Finding.status.in_(["open","triaged","assigned","in_remediation"]))) or 0
    critical=await db.scalar(select(func.count()).select_from(Finding).join(Scan).where(Scan.workspace_id==ws,Finding.severity=="critical",Finding.status.not_in(["closed","false_positive"]))) or 0
    return {"workspace_id":ws,"assets":assets,"scans":scans,"findings":findings,"open_findings":open_findings,"critical_findings":critical}
