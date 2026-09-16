from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends
from ..auth import LoginRequest,Principal,issue_token
from ..config import settings
from ..database import get_db
from ..models import User,Workspace,WorkspaceMember
router=APIRouter(prefix="/api/v1/auth",tags=["auth"])
class LoginResponse(BaseModel):
    access_token:str; token_type:str="bearer"; actor:str; role:str; workspace_id:str; user_id:str
@router.post("/login",response_model=LoginResponse)
async def login(payload:LoginRequest,db:AsyncSession=Depends(get_db)):
    email=payload.email.strip().lower(); user=await db.scalar(select(User).where(User.email==email,User.is_active.is_(True)))
    if user:
        import hmac
        if not hmac.compare_digest(user.password_hash,__import__('hashlib').sha256(payload.password.encode()).hexdigest()): raise HTTPException(401,"Invalid credentials")
        member=await db.scalar(select(WorkspaceMember).where(WorkspaceMember.user_id==user.id,WorkspaceMember.workspace_id==payload.workspace_id))
        if not member: raise HTTPException(403,"User is not a member of this workspace")
        principal=Principal(email,member.role,payload.workspace_id,user.id)
    else:
        if email!=settings.BOOTSTRAP_EMAIL.lower() or not hmac.compare_digest(__import__('hashlib').sha256(payload.password.encode()).hexdigest(),__import__('hashlib').sha256(settings.BOOTSTRAP_PASSWORD.encode()).hexdigest()): raise HTTPException(401,"Invalid credentials")
        principal=Principal(email,settings.BOOTSTRAP_ROLE,payload.workspace_id,None)
    return LoginResponse(access_token=issue_token(principal.actor,principal.role,principal.workspace_id,principal.user_id),actor=principal.actor,role=principal.role,workspace_id=principal.workspace_id,user_id=principal.user_id or "bootstrap")
