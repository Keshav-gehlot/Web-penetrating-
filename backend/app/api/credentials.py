from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Principal
from ..config import settings
from ..database import get_db
from ..models import AssessmentCredential
from ..rbac import require_permission
from ..security import decrypt_credential, encrypt_credential
from .audit import record_audit

router = APIRouter(prefix="/api/v1/workspaces/current/credentials", tags=["credentials"])

class CredentialCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: str = Field(pattern="^(basic|bearer|api_key)$")
    username: str | None = Field(default=None, max_length=255)
    header_name: str | None = Field(default=None, max_length=64)
    secret: SecretStr

def serialize(row: AssessmentCredential) -> dict:
    return {"id": row.id, "name": row.name, "kind": row.kind, "username": row.username,
            "header_name": row.header_name, "created_at": row.created_at.isoformat() if row.created_at else None,
            "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None}

def _validate(payload: CredentialCreate) -> None:
    if payload.kind == "basic" and not payload.username:
        raise HTTPException(400, "Basic credentials require a username")
    if payload.kind == "api_key" and payload.header_name not in {"Authorization", None} and not (payload.header_name or "").startswith("X-"):
        raise HTTPException(400, "API key header must be Authorization or an X-* header")

@router.get("")
async def list_credentials(principal: Principal = Depends(require_permission("scan:view")), db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(AssessmentCredential).where(AssessmentCredential.workspace_id == principal.workspace_id).order_by(AssessmentCredential.created_at.desc()))
    return [serialize(row) for row in rows.all()]

@router.post("")
async def create_credential(payload: CredentialCreate, request: Request, principal: Principal = Depends(require_permission("scan:credentials")), db: AsyncSession = Depends(get_db)):
    _validate(payload)
    exists = await db.scalar(select(AssessmentCredential).where(AssessmentCredential.workspace_id == principal.workspace_id, AssessmentCredential.name == payload.name))
    if exists:
        raise HTTPException(409, "Credential name already exists")
    row = AssessmentCredential(id=str(uuid4()), workspace_id=principal.workspace_id, name=payload.name, kind=payload.kind,
        username=payload.username, header_name=payload.header_name or ("Authorization" if payload.kind in {"bearer","api_key"} else None),
        secret_ciphertext=encrypt_credential(payload.secret.get_secret_value(), settings.CREDENTIAL_ENCRYPTION_KEY), created_by=principal.user_id)
    db.add(row)
    await record_audit(db, request, "credential.created", "assessment_credential", row.id, {"name": row.name, "kind": row.kind}, principal)
    await db.commit()
    await db.refresh(row)
    return serialize(row)

@router.post("/{credential_id}/rotate")
async def rotate_credential(credential_id: str, payload: CredentialCreate, request: Request, principal: Principal = Depends(require_permission("scan:credentials")), db: AsyncSession = Depends(get_db)):
    _validate(payload)
    row = await db.scalar(select(AssessmentCredential).where(AssessmentCredential.id == credential_id, AssessmentCredential.workspace_id == principal.workspace_id))
    if not row:
        raise HTTPException(404, "Credential not found")
    row.kind = payload.kind
    row.username = payload.username
    row.header_name = payload.header_name or ("Authorization" if payload.kind in {"bearer","api_key"} else None)
    row.secret_ciphertext = encrypt_credential(payload.secret.get_secret_value(), settings.CREDENTIAL_ENCRYPTION_KEY)
    await record_audit(db, request, "credential.rotated", "assessment_credential", row.id, {"kind": row.kind}, principal)
    await db.commit()
    await db.refresh(row)
    return serialize(row)

@router.delete("/{credential_id}")
async def delete_credential(credential_id: str, request: Request, principal: Principal = Depends(require_permission("scan:credentials")), db: AsyncSession = Depends(get_db)):
    row = await db.scalar(select(AssessmentCredential).where(AssessmentCredential.id == credential_id, AssessmentCredential.workspace_id == principal.workspace_id))
    if not row:
        raise HTTPException(404, "Credential not found")
    await record_audit(db, request, "credential.deleted", "assessment_credential", row.id, {"name": row.name}, principal)
    await db.execute(delete(AssessmentCredential).where(AssessmentCredential.id == row.id))
    await db.commit()
    return {"deleted": True}
