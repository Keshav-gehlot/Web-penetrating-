from __future__ import annotations
from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import Principal
from ..database import get_db
from ..models import AssessmentCredential
from ..rbac import require_permission
from ..security import encrypt_credential
from .audit import record_audit

router=APIRouter(prefix="/api/v1/workspaces/current/credentials",tags=["credentials"])

class CredentialCreate(BaseModel):
    name:str=Field(min_length=1,max_length=120)
    kind:str=Field(pattern="^(basic|bearer|api_key)$")
    secret:SecretStr=Field(min_length=1,max_length=4096)
    username:str|None=Field(default=None,max_length=255)
    header_name:str|None=Field(default=None,max_length=100)

class CredentialRotate(BaseModel):
    secret:SecretStr=Field(min_length=1,max_length=4096)
    username:str|None=Field(default=None,max_length=255)
    header_name:str|None=Field(default=None,max_length=100)

def _validate_header(kind:str,header_name:str|None)->str|None:
    if kind!="api_key":
        return None
    value=(header_name or "X-API-Key").strip()
    if not value or "\r" in value or "\n" in value or ":" in value:
        raise HTTPException(400,"Invalid API key header name")
    if not (value.lower()=="authorization" or value.lower().startswith("x-")):
        raise HTTPException(400,"API key header must be Authorization or an X-* header")
    return value

def _serialize(c:AssessmentCredential)->dict:
    return {
        "id":c.id,"name":c.name,"kind":c.kind,"username":c.username,
        "header_name":c.header_name,"created_at":c.created_at.isoformat() if c.created_at else None,
        "last_used_at":c.last_used_at.isoformat() if c.last_used_at else None,
        "secret_configured":True,
    }

@router.get("")
async def list_credentials(principal:Principal=Depends(require_permission("scan:credentials")),db:AsyncSession=Depends(get_db)):
    rows=await db.scalars(select(AssessmentCredential).where(AssessmentCredential.workspace_id==principal.workspace_id).order_by(AssessmentCredential.created_at.desc()))
    return [_serialize(c) for c in rows.all()]

@router.post("")
async def create_credential(payload:CredentialCreate,request:Request,principal:Principal=Depends(require_permission("scan:credentials")),db:AsyncSession=Depends(get_db)):
    if not principal.user_id:
        raise HTTPException(401,"Authenticated user identity is required")
    existing=await db.scalar(select(AssessmentCredential).where(AssessmentCredential.workspace_id==principal.workspace_id,AssessmentCredential.name==payload.name.strip()))
    if existing:
        raise HTTPException(409,"Credential name already exists in this workspace")
    if payload.kind=="basic" and not (payload.username or "").strip():
        raise HTTPException(400,"Basic authentication credentials require a username")
    header=_validate_header(payload.kind,payload.header_name)
    try:
        ciphertext=encrypt_credential(payload.secret.get_secret_value())
    except RuntimeError as exc:
        raise HTTPException(503,str(exc)) from exc
    credential=AssessmentCredential(
        id=str(uuid4()),workspace_id=principal.workspace_id,name=payload.name.strip(),
        kind=payload.kind,username=payload.username.strip() if payload.username else None,
        header_name=header,secret_ciphertext=ciphertext,created_by=principal.user_id)
    db.add(credential);await db.flush()
    await record_audit(db,request,"credential.created","assessment_credential",credential.id,
                       {"name":credential.name,"kind":credential.kind},principal)
    await db.commit()
    return _serialize(credential)

@router.post("/{credential_id}/rotate")
async def rotate_credential(credential_id:str,payload:CredentialRotate,request:Request,principal:Principal=Depends(require_permission("scan:credentials")),db:AsyncSession=Depends(get_db)):
    credential=await db.scalar(select(AssessmentCredential).where(AssessmentCredential.id==credential_id,AssessmentCredential.workspace_id==principal.workspace_id))
    if not credential:
        raise HTTPException(404,"Credential not found")
    if credential.kind=="basic" and not ((payload.username or credential.username or "").strip()):
        raise HTTPException(400,"Basic authentication credentials require a username")
    header=_validate_header(credential.kind,payload.header_name if payload.header_name is not None else credential.header_name)
    try:
        credential.secret_ciphertext=encrypt_credential(payload.secret.get_secret_value())
    except RuntimeError as exc:
        raise HTTPException(503,str(exc)) from exc
    if payload.username is not None:
        credential.username=payload.username.strip() or None
    credential.header_name=header
    await record_audit(db,request,"credential.rotated","assessment_credential",credential.id,
                       {"name":credential.name,"kind":credential.kind},principal)
    await db.commit()
    return _serialize(credential)

@router.delete("/{credential_id}")
async def delete_credential(credential_id:str,request:Request,principal:Principal=Depends(require_permission("scan:credentials")),db:AsyncSession=Depends(get_db)):
    credential=await db.scalar(select(AssessmentCredential).where(AssessmentCredential.id==credential_id,AssessmentCredential.workspace_id==principal.workspace_id))
    if not credential:
        raise HTTPException(404,"Credential not found")
    await record_audit(db,request,"credential.deleted","assessment_credential",credential.id,
                       {"name":credential.name,"kind":credential.kind},principal)
    await db.delete(credential);await db.commit()
    return {"deleted":True}
