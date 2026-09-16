from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import LoginRequest, Principal, issue_token
from ..config import settings
from ..database import get_db
from ..models import User, WorkspaceMember
from ..security import hash_password, is_legacy_sha256, verify_legacy_sha256, verify_password
router=APIRouter(prefix="/api/v1/auth",tags=["auth"])
class LoginResponse(BaseModel):
    access_token:str; token_type:str="bearer"; actor:str; role:str; workspace_id:str; user_id:str
@router.post("/login",response_model=LoginResponse)
async def login(payload:LoginRequest,db:AsyncSession=Depends(get_db)):
    email=payload.email.strip().lower(); user=await db.scalar(select(User).where(User.email==email,User.is_active.is_(True)))
    if not user: raise HTTPException(401,"Invalid credentials")
    valid=verify_password(payload.password,user.password_hash)
    if not valid and is_legacy_sha256(user.password_hash):
        valid=verify_legacy_sha256(payload.password,user.password_hash)
        if valid:
            user.password_hash=hash_password(payload.password);await db.commit()
    if not valid: raise HTTPException(401,"Invalid credentials")
    member=await db.scalar(select(WorkspaceMember).where(WorkspaceMember.user_id==user.id,WorkspaceMember.workspace_id==payload.workspace_id))
    if not member: raise HTTPException(403,"User is not a member of this workspace")
    principal=Principal(email,member.role,member.workspace_id,user.id)
    return LoginResponse(access_token=issue_token(principal.actor,principal.role,principal.workspace_id,principal.user_id),actor=principal.actor,role=principal.role,workspace_id=principal.workspace_id,user_id=principal.user_id or "")
