from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import Principal
from ..database import get_db
from ..models import Finding, Scan
from ..rbac import require_permission
router=APIRouter(prefix="/api/v1/investigations",tags=["investigations"])
class NoteUpdate(BaseModel):note:str=Field(max_length=20000)
@router.get("/{finding_id}")
async def investigation(finding_id:str,principal:Principal=Depends(require_permission("finding:view")),db:AsyncSession=Depends(get_db)):
    finding=await db.scalar(select(Finding).join(Scan).where(Finding.id==finding_id,Scan.workspace_id==principal.workspace_id))
    if not finding:raise HTTPException(404,"Finding not found")
    scan=await db.get(Scan,finding.scan_id)
    history_rows=await db.scalars(select(Finding).join(Scan).where(Finding.fingerprint==finding.fingerprint,Scan.workspace_id==principal.workspace_id).order_by(Finding.created_at.desc()).limit(50))
    history=[{"id":f.id,"scan_id":f.scan_id,"status":f.status,"severity":f.severity,"first_seen":f.first_seen.isoformat() if f.first_seen else None,"last_seen":f.last_seen.isoformat() if f.last_seen else None} for f in history_rows.all()]
    return {"finding":{"id":finding.id,"scan_id":finding.scan_id,"module":finding.module,"title":finding.title,"severity":finding.severity,"status":finding.status,"cve":finding.cve,"cwe":finding.cwe,"cvss":finding.cvss,"assignee":finding.assignee,"description":finding.description,"remediation":finding.remediation,"evidence":finding.evidence,"confidence":finding.confidence},"target":{"host":scan.host,"target":scan.target,"profile":scan.profile},"history":history,"timeline":[{"event":"finding_created","at":finding.first_seen.isoformat() if finding.first_seen else None},{"event":"last_observed","at":finding.last_seen.isoformat() if finding.last_seen else None}]}
@router.patch("/{finding_id}/notes")
async def save_note(finding_id:str,payload:NoteUpdate,principal:Principal=Depends(require_permission("finding:edit")),db:AsyncSession=Depends(get_db)):
    finding=await db.scalar(select(Finding).join(Scan).where(Finding.id==finding_id,Scan.workspace_id==principal.workspace_id))
    if not finding:raise HTTPException(404,"Finding not found")
    evidence=dict(finding.evidence or {});evidence["analyst_note"]=payload.note;evidence["note_updated_at"]=datetime.now(timezone.utc).isoformat();finding.evidence=evidence;await db.commit();return {"finding_id":finding_id,"saved":True,"updated_at":evidence["note_updated_at"]}
