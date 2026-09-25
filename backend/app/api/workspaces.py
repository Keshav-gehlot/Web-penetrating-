from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import Principal
from ..database import get_db
from ..models import User, WorkspaceMember
from ..rbac import require_permission
from ..security import hash_password
from .audit import record_audit
router=APIRouter(prefix="/api/v1/workspaces",tags=["workspaces"])
class MemberCreate(BaseModel):
    email:str=Field(min_length=3,max_length=255);role:str=Field(pattern="^(owner|admin|security_lead|analyst|developer|viewer)$");name:str=Field(min_length=1,max_length=120);password:str=Field(min_length=8,max_length=256)
class MemberRoleUpdate(BaseModel):role:str=Field(pattern="^(owner|admin|security_lead|analyst|developer|viewer)$")
@router.get("/current")
async def current(principal:Principal=Depends(require_permission("scan:view")),db:AsyncSession=Depends(get_db)):
    count=await db.scalar(select(__import__('sqlalchemy').func.count()).select_from(WorkspaceMember).where(WorkspaceMember.workspace_id==principal.workspace_id)) or 0
    return {"id":principal.workspace_id,"name":"PHANTOM Security Workspace","actor":principal.actor,"role":principal.role,"members":count}
@router.get("/current/members")
async def members(principal:Principal=Depends(require_permission("scan:view")),db:AsyncSession=Depends(get_db)):
    rows=await db.scalars(select(WorkspaceMember).options(selectinload(WorkspaceMember.user)).where(WorkspaceMember.workspace_id==principal.workspace_id));return [{"id":m.id,"email":m.user.email,"name":m.user.display_name,"role":m.role,"active":m.user.is_active} for m in rows.all()]
@router.post("/current/members")
async def add_member(payload:MemberCreate,request:Request,principal:Principal=Depends(require_permission("users:manage")),db:AsyncSession=Depends(get_db)):
    email=payload.email.strip().lower();user=await db.scalar(select(User).where(User.email==email))
    if user and await db.scalar(select(WorkspaceMember).where(WorkspaceMember.workspace_id==principal.workspace_id,WorkspaceMember.user_id==user.id)):raise HTTPException(409,"Member already exists")
    if not user:user=User(email=email,display_name=payload.name,password_hash=hash_password(payload.password));db.add(user);await db.flush()
    m=WorkspaceMember(workspace_id=principal.workspace_id,user_id=user.id,role=payload.role);db.add(m);await db.flush();await record_audit(db,request,"workspace.member_added","workspace_member",m.id,{"email":email,"role":payload.role},principal);await db.commit();return {"id":m.id,"email":email,"name":user.display_name,"role":m.role}
@router.patch("/current/members/{member_id}")
async def change_role(member_id:str,payload:MemberRoleUpdate,request:Request,principal:Principal=Depends(require_permission("users:manage")),db:AsyncSession=Depends(get_db)):
    m=await db.get(WorkspaceMember,member_id)
    if not m or m.workspace_id!=principal.workspace_id:raise HTTPException(404,"Member not found")
    old=m.role;m.role=payload.role;await record_audit(db,request,"workspace.member_role_changed","workspace_member",m.id,{"from":old,"to":m.role},principal);await db.commit();return {"id":m.id,"role":m.role}
@router.delete("/current/members/{member_id}")
async def remove_member(member_id:str,request:Request,principal:Principal=Depends(require_permission("users:manage")),db:AsyncSession=Depends(get_db)):
    m=await db.get(WorkspaceMember,member_id)
    if not m or m.workspace_id!=principal.workspace_id:raise HTTPException(404,"Member not found")
    user=await db.get(User,m.user_id);m_id=m.id
    if user:user.is_active=False
    await db.delete(m);await record_audit(db,request,"workspace.member_removed","workspace_member",m_id,None,principal);await db.commit();return {"removed":True}
