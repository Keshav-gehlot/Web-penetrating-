from __future__ import annotations
import hashlib
import json
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..api.audit import record_audit
from ..auth import Principal
from ..database import get_db
from ..models import Finding, Scan
from ..rbac import require_permission
router=APIRouter(prefix="/api/v1/findings",tags=["findings"])
STATUSES={"open","triaged","assigned","in_remediation","fixed","verified","closed","accepted_risk","false_positive"}
TRANSITIONS={"open":{"triaged","accepted_risk","false_positive"},"triaged":{"assigned","in_remediation","accepted_risk","false_positive","open"},"assigned":{"in_remediation","triaged","accepted_risk","false_positive"},"in_remediation":{"fixed","assigned","accepted_risk"},"fixed":{"verified","in_remediation"},"verified":{"closed","in_remediation"},"closed":{"open"},"accepted_risk":{"open","triaged"},"false_positive":{"open","triaged"}}
class FindingUpdate(BaseModel):status:str|None=Field(default=None);assignee:str|None=Field(default=None,max_length=255)
def evidence_digest(evidence:dict|None)->str:
    canonical=json.dumps(evidence or {},sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
def serialize(f):
    return {
        "id": f.id, "scan_id": f.scan_id, "module": f.module, "title": f.title,
        "severity": f.severity, "status": f.status, "fingerprint": f.fingerprint,
        "cve": f.cve, "cwe": f.cwe, "cvss": f.cvss,
        "product": f.product, "version": f.version, "cpe": f.cpe,
        "cvss_v3": {"score": f.cvss_v3_score, "vector": f.cvss_v3_vector, "severity": f.cvss_v3_severity} if f.cvss_v3_score is not None else None,
        "cvss_v4": {"score": f.cvss_v4_score, "vector": f.cvss_v4_vector, "severity": f.cvss_v4_severity} if f.cvss_v4_score is not None else None,
        "cve_published_at": f.cve_published_at.isoformat() if f.cve_published_at else None,
        "cve_modified_at": f.cve_modified_at.isoformat() if f.cve_modified_at else None,
        "affected_versions": f.cve_affected_versions or [], "references": f.cve_references or [],
        "assignee": f.assignee, "description": f.description, "remediation": f.remediation,
        "evidence": f.evidence, "evidence_hash": f.evidence_hash,
        "evidence_collected_at": f.evidence_collected_at.isoformat() if f.evidence_collected_at else None,
        "evidence_source": f.evidence_source, "confidence": f.confidence,
    }
def fingerprint_for(scan:Scan,item:dict)->str:
 evidence=item.get("evidence") or {};stable=evidence.get("url") or evidence.get("path") or evidence.get("host") or "";return hashlib.sha256(f"{scan.host}|{item.get('module','')}|{item.get('title','')}|{stable}".lower().encode()).hexdigest()
def scoped_finding(finding_id,workspace_id,db):return db.scalar(select(Finding).join(Scan).where(Finding.id==finding_id,Scan.workspace_id==workspace_id))
@router.get("")
async def list_findings(status:str|None=None,severity:str|None=None,principal:Principal=Depends(require_permission("finding:view")),db:AsyncSession=Depends(get_db)):
 q=select(Finding).join(Scan).where(Scan.workspace_id==principal.workspace_id).order_by(Finding.last_seen.desc()).limit(500)
 if status:q=q.where(Finding.status==status)
 if severity:q=q.where(Finding.severity==severity)
 rows=await db.scalars(q);return [serialize(f) for f in rows.all()]
@router.get("/{finding_id}")
async def get_finding(finding_id:str,principal:Principal=Depends(require_permission("finding:view")),db:AsyncSession=Depends(get_db)):
 f=await scoped_finding(finding_id,principal.workspace_id,db)
 if not f:raise HTTPException(404,"Finding not found")
 return serialize(f)
@router.patch("/{finding_id}")
async def update_finding(finding_id:str,update:FindingUpdate,request:Request,principal:Principal=Depends(require_permission("finding:edit")),db:AsyncSession=Depends(get_db)):
 f=await scoped_finding(finding_id,principal.workspace_id,db)
 if not f:raise HTTPException(404,"Finding not found")
 changes={}
 if update.status is not None:
  if update.status not in STATUSES:raise HTTPException(400,"Invalid finding status")
  if update.status!=f.status and update.status not in TRANSITIONS.get(f.status,set()):raise HTTPException(409,f"Invalid lifecycle transition: {f.status} -> {update.status}")
  changes["status"]=[f.status,update.status];f.status=update.status
 if update.assignee is not None:
  if principal.role not in {"owner","admin","security_lead","analyst"}:raise HTTPException(403,"Role cannot assign findings")
  changes["assignee"]=[f.assignee,update.assignee.strip() or None];f.assignee=update.assignee.strip() or None
 await record_audit(db,request,"finding.updated","finding",f.id,changes,principal);await db.commit();await db.refresh(f);return serialize(f)
