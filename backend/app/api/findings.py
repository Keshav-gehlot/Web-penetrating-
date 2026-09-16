from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.audit import record_audit
from ..database import get_db
from ..models import Finding, Scan
from ..rbac import require_permission

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])
STATUSES = {"open", "triaged", "assigned", "in_remediation", "fixed", "verified", "closed", "accepted_risk", "false_positive"}
TRANSITIONS = {
    "open": {"triaged", "accepted_risk", "false_positive"},
    "triaged": {"assigned", "in_remediation", "accepted_risk", "false_positive", "open"},
    "assigned": {"in_remediation", "triaged", "accepted_risk", "false_positive"},
    "in_remediation": {"fixed", "assigned", "accepted_risk"},
    "fixed": {"verified", "in_remediation"},
    "verified": {"closed", "in_remediation"},
    "closed": {"open"},
    "accepted_risk": {"open", "triaged"},
    "false_positive": {"open", "triaged"},
}
class FindingUpdate(BaseModel):
    status: str | None = Field(default=None)
    assignee: str | None = Field(default=None, max_length=255)

def serialize(f: Finding) -> dict:
    return {"id": f.id, "scan_id": f.scan_id, "module": f.module, "title": f.title, "severity": f.severity, "status": f.status, "fingerprint": f.fingerprint, "cve": f.cve, "cwe": f.cwe, "cvss": f.cvss, "assignee": f.assignee, "description": f.description, "remediation": f.remediation, "evidence": f.evidence, "confidence": f.confidence, "first_seen": f.first_seen.isoformat() if f.first_seen else None, "last_seen": f.last_seen.isoformat() if f.last_seen else None}

def fingerprint_for(scan: Scan, item: dict) -> str:
    evidence = item.get("evidence") or {}
    stable = evidence.get("url") or evidence.get("path") or evidence.get("host") or ""
    raw = f"{scan.host}|{item.get('module','')}|{item.get('title','')}|{stable}".lower()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

@router.get("", dependencies=[Depends(require_permission("finding:view"))])
async def list_findings(status: str | None = None, severity: str | None = None, db: AsyncSession = Depends(get_db)):
    query = select(Finding).order_by(Finding.last_seen.desc()).limit(500)
    if status: query = query.where(Finding.status == status)
    if severity: query = query.where(Finding.severity == severity)
    rows = await db.scalars(query)
    return [serialize(f) for f in rows.all()]

@router.get("/{finding_id}", dependencies=[Depends(require_permission("finding:view"))])
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    finding = await db.get(Finding, finding_id)
    if not finding: raise HTTPException(404, "Finding not found")
    return serialize(finding)

@router.patch("/{finding_id}")
async def update_finding(finding_id: str, update: FindingUpdate, request: Request, db: AsyncSession = Depends(get_db), _role=Depends(require_permission("finding:edit"))):
    finding = await db.get(Finding, finding_id)
    if not finding: raise HTTPException(404, "Finding not found")
    changes = {}
    if update.status is not None:
        if update.status not in STATUSES: raise HTTPException(400, "Invalid finding status")
        if update.status != finding.status and update.status not in TRANSITIONS.get(finding.status, set()): raise HTTPException(409, f"Invalid lifecycle transition: {finding.status} -> {update.status}")
        changes["status"] = [finding.status, update.status]
        finding.status = update.status
    if update.assignee is not None:
        if _role not in {"owner", "admin", "security_lead", "analyst"}: raise HTTPException(403, "Role cannot assign findings")
        changes["assignee"] = [finding.assignee, update.assignee.strip() or None]
        finding.assignee = update.assignee.strip() or None
    finding.last_seen = datetime.now(timezone.utc)
    await record_audit(db, request, "finding.updated", "finding", finding.id, changes)
    await db.commit()
    await db.refresh(finding)
    return serialize(finding)
