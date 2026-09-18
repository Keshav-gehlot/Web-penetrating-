from __future__ import annotations
from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..api.audit import record_audit
from ..auth import Principal
from ..database import get_db
from ..models import Asset, AssetHistory, AssetService, Finding, FindingNote, Scan
from ..rbac import require_permission

router=APIRouter(prefix="/api/v1/investigations",tags=["investigations"])

class NoteUpdate(BaseModel):
    note:str=Field(max_length=20000)

def serialize_note(note:FindingNote)->dict:
    return {"id":note.id,"author_id":note.author_id,"note":note.note,"created_at":note.created_at.isoformat() if note.created_at else None,"updated_at":note.updated_at.isoformat() if note.updated_at else None}

@router.get("/{finding_id}")
async def investigation(finding_id:str,principal:Principal=Depends(require_permission("finding:view")),db:AsyncSession=Depends(get_db)):
    finding=await db.scalar(select(Finding).join(Scan).where(Finding.id==finding_id,Scan.workspace_id==principal.workspace_id))
    if not finding:raise HTTPException(404,"Finding not found")
    scan=await db.get(Scan,finding.scan_id)
    asset=await db.scalar(select(Asset).where(Asset.id==scan.asset_id,Asset.workspace_id==principal.workspace_id)) if scan and scan.asset_id else None
    services=[]
    asset_history=[]
    if asset:
        service_rows=await db.scalars(select(AssetService).where(AssetService.asset_id==asset.id).order_by(AssetService.port))
        services=[{"port":s.port,"protocol":s.protocol,"service":s.service,"state":s.state,"last_seen_at":s.last_seen_at.isoformat() if s.last_seen_at else None} for s in service_rows.all()]
        history_rows=await db.scalars(select(AssetHistory).where(AssetHistory.asset_id==asset.id,AssetHistory.workspace_id==principal.workspace_id).order_by(AssetHistory.created_at.desc()).limit(50))
        asset_history=[{"event_type":h.event_type,"scan_id":h.scan_id,"metadata":h.metadata_json,"created_at":h.created_at.isoformat() if h.created_at else None} for h in history_rows.all()]
    history_rows=await db.scalars(select(Finding).join(Scan).where(Finding.fingerprint==finding.fingerprint,Scan.workspace_id==principal.workspace_id).order_by(Finding.created_at.desc()).limit(50))
    note_rows=await db.scalars(select(FindingNote).where(FindingNote.finding_id==finding.id,FindingNote.workspace_id==principal.workspace_id).order_by(FindingNote.updated_at.desc()).limit(50))
    history=[{"id":f.id,"scan_id":f.scan_id,"status":f.status,"severity":f.severity,"first_seen":f.first_seen.isoformat() if f.first_seen else None,"last_seen":f.last_seen.isoformat() if f.last_seen else None} for f in history_rows.all()]
    notes=[serialize_note(n) for n in note_rows.all()]
    return {"finding":{"id":finding.id,"scan_id":finding.scan_id,"module":finding.module,"title":finding.title,"severity":finding.severity,"status":finding.status,"cve":finding.cve,"cwe":finding.cwe,"cvss":finding.cvss,"assignee":finding.assignee,"description":finding.description,"remediation":finding.remediation,"evidence":finding.evidence,"evidence_hash":finding.evidence_hash,"evidence_collected_at":finding.evidence_collected_at.isoformat() if finding.evidence_collected_at else None,"evidence_source":finding.evidence_source,"confidence":finding.confidence},"target":{"host":scan.host,"target":scan.target,"profile":scan.profile},"asset":({"id":asset.id,"host":asset.host,"addresses":asset.addresses,"type":asset.asset_type,"environment":asset.environment,"criticality":asset.criticality,"owner":asset.owner,"services":services,"history":asset_history} if asset else None),"history":history,"notes":notes,"timeline":[{"event":"finding_created","at":finding.first_seen.isoformat() if finding.first_seen else None},{"event":"last_observed","at":finding.last_seen.isoformat() if finding.last_seen else None}]}

@router.patch("/{finding_id}/notes")
async def save_note(finding_id:str,payload:NoteUpdate,request:Request,principal:Principal=Depends(require_permission("finding:edit")),db:AsyncSession=Depends(get_db)):
    finding=await db.scalar(select(Finding).join(Scan).where(Finding.id==finding_id,Scan.workspace_id==principal.workspace_id))
    if not finding:raise HTTPException(404,"Finding not found")
    now=datetime.now(timezone.utc)
    note=await db.scalar(select(FindingNote).where(FindingNote.finding_id==finding.id,FindingNote.workspace_id==principal.workspace_id,FindingNote.author_id==principal.user_id).order_by(FindingNote.updated_at.desc()).limit(1))
    if note:
        note.note=payload.note
        note.updated_at=now
    else:
        note=FindingNote(id=str(uuid4()),finding_id=finding.id,workspace_id=principal.workspace_id,author_id=principal.user_id,note=payload.note,created_at=now,updated_at=now)
        db.add(note)
    await record_audit(db,request,"finding.note_updated","finding",finding.id,{"note_id":note.id,"length":len(payload.note)},principal)
    await db.commit();await db.refresh(note)
    return {"finding_id":finding_id,"saved":True,"note":serialize_note(note)}
