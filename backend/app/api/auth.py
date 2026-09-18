from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib, secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import LoginRequest, Principal, issue_token, current_principal
from ..config import settings
from ..database import get_db
from ..models import User, WorkspaceMember, AuthSession, PasswordResetToken, EmailVerificationToken, AuthInvitation
from ..security import hash_password, is_legacy_sha256, verify_legacy_sha256, verify_password
from .audit import record_audit
router=APIRouter(prefix="/api/v1/auth",tags=["auth"])
LOCK_MINUTES=15
MAX_FAILURES=5
def _hash_token(token:str)->str: return hashlib.sha256(token.encode()).hexdigest()
def _now(): return datetime.now(timezone.utc)
class LoginResponse(BaseModel):
    access_token:str; refresh_token:str; token_type:str="bearer"; actor:str; role:str; workspace_id:str; user_id:str; expires_at:str
class RefreshRequest(BaseModel): refresh_token:str=Field(min_length=20,max_length=512)
class PasswordChangeRequest(BaseModel): current_password:str=Field(min_length=8,max_length=256); new_password:str=Field(min_length=8,max_length=256)
class PasswordResetRequest(BaseModel): email:str=Field(min_length=3,max_length=255)
class PasswordResetConfirm(BaseModel): token:str=Field(min_length=20,max_length=512); new_password:str=Field(min_length=8,max_length=256)
class VerifyEmailRequest(BaseModel): token:str=Field(min_length=20,max_length=512)
class InvitationAccept(BaseModel): token:str=Field(min_length=20,max_length=512);password:str=Field(min_length=8,max_length=256)
async def _session_response(user, member, db, request):
    sid=secrets.token_urlsafe(18); refresh=secrets.token_urlsafe(48); now=_now(); exp=now+timedelta(hours=settings.SESSION_HOURS)
    s=AuthSession(user_id=user.id,workspace_id=member.workspace_id,refresh_token_hash=_hash_token(refresh),access_token_id=sid,user_agent=request.headers.get("user-agent"),ip_address=request.client.host if request.client else None,expires_at=exp)
    db.add(s); await db.flush()
    access=issue_token(user.email,member.role,member.workspace_id,user.id,hours=settings.SESSION_HOURS,session_id=s.id)
    return LoginResponse(access_token=access,refresh_token=refresh,actor=user.email,role=member.role,workspace_id=member.workspace_id,user_id=user.id,expires_at=exp.isoformat())
@router.post("/login",response_model=LoginResponse)
async def login(payload:LoginRequest,request:Request,db:AsyncSession=Depends(get_db)):
    email=payload.email.strip().lower(); user=await db.scalar(select(User).where(User.email==email))
    if not user or not user.is_active: raise HTTPException(401,"Invalid credentials")
    now=_now()
    if user.locked_until and user.locked_until>now: raise HTTPException(429,"Account temporarily locked. Try again later.")
    valid=verify_password(payload.password,user.password_hash)
    if not valid and is_legacy_sha256(user.password_hash): valid=verify_legacy_sha256(payload.password,user.password_hash); user.password_hash=hash_password(payload.password) if valid else user.password_hash
    if not valid:
        user.failed_login_count += 1
        if user.failed_login_count>=MAX_FAILURES: user.locked_until=now+timedelta(minutes=LOCK_MINUTES); user.failed_login_count=0
        await record_audit(db,request,"auth.login_failed","user",user.id,{"email":email},actor=email); await db.commit(); raise HTTPException(401,"Invalid credentials")
    user.failed_login_count=0; user.locked_until=None
    member=await db.scalar(select(WorkspaceMember).where(WorkspaceMember.user_id==user.id,WorkspaceMember.workspace_id==payload.workspace_id))
    if not member: await db.commit(); raise HTTPException(403,"User is not a member of this workspace")
    response=await _session_response(user,member,db,request); await record_audit(db,request,"auth.login","auth_session",response.user_id,{"workspace_id":member.workspace_id},actor=user.email); await db.commit(); return response
@router.post("/refresh",response_model=LoginResponse)
async def refresh(payload:RefreshRequest,request:Request,db:AsyncSession=Depends(get_db)):
    s=await db.scalar(select(AuthSession).where(AuthSession.refresh_token_hash==_hash_token(payload.refresh_token),AuthSession.revoked_at.is_(None),AuthSession.expires_at>=_now()))
    if not s: raise HTTPException(401,"Refresh token expired or revoked")
    user=await db.scalar(select(User).where(User.id==s.user_id,User.is_active.is_(True))); member=await db.scalar(select(WorkspaceMember).where(WorkspaceMember.user_id==s.user_id,WorkspaceMember.workspace_id==s.workspace_id))
    if not user or not member: s.revoked_at=_now(); await db.commit(); raise HTTPException(401,"Session is no longer active")
    s.revoked_at=_now(); response=await _session_response(user,member,db,request); await record_audit(db,request,"auth.session_refreshed","auth_session",s.id,None,actor=user.email); await db.commit(); return response
@router.post("/logout")
async def logout(principal:Principal=Depends(current_principal),request:Request=None,db:AsyncSession=Depends(get_db)):
    s=await db.get(AuthSession,principal.session_id);
    if s and not s.revoked_at: s.revoked_at=_now(); await record_audit(db,request,"auth.logout","auth_session",s.id,None,principal)
    await db.commit(); return {"revoked":True}
@router.post("/sessions/revoke-all")
async def revoke_all(principal:Principal=Depends(current_principal),request:Request=None,db:AsyncSession=Depends(get_db)):
    rows=await db.scalars(select(AuthSession).where(AuthSession.user_id==principal.user_id,AuthSession.revoked_at.is_(None))); now=_now(); count=0
    for s in rows.all(): s.revoked_at=now; count+=1
    await record_audit(db,request,"auth.sessions_revoked_all","user",principal.user_id,{"count":count},principal); await db.commit(); return {"revoked":count}
@router.post("/password/change")
async def change_password(payload:PasswordChangeRequest,principal:Principal=Depends(current_principal),request:Request=None,db:AsyncSession=Depends(get_db)):
    user=await db.get(User,principal.user_id)
    if not user or not verify_password(payload.current_password,user.password_hash): raise HTTPException(400,"Current password is incorrect")
    if payload.current_password==payload.new_password: raise HTTPException(400,"New password must differ from current password")
    user.password_hash=hash_password(payload.new_password)
    rows=await db.scalars(select(AuthSession).where(AuthSession.user_id==user.id,AuthSession.id!=principal.session_id,AuthSession.revoked_at.is_(None)))
    for s in rows.all(): s.revoked_at=_now()
    await record_audit(db,request,"auth.password_changed","user",user.id,None,principal); await db.commit(); return {"changed":True,"other_sessions_revoked":True}
@router.post("/password/reset/request")
async def reset_request(payload:PasswordResetRequest,request:Request,db:AsyncSession=Depends(get_db)):
    email=payload.email.strip().lower(); user=await db.scalar(select(User).where(User.email==email,User.is_active.is_(True)))
    token=secrets.token_urlsafe(48)
    if user: db.add(PasswordResetToken(user_id=user.id,token_hash=_hash_token(token),expires_at=_now()+timedelta(minutes=30))); await record_audit(db,request,"auth.password_reset_requested","user",user.id,None,actor=email)
    await db.commit()
    return {"accepted":True,"message":"If the account exists, reset instructions have been issued.","development_token":token if settings.ENVIRONMENT!="production" and user else None}
@router.post("/password/reset/confirm")
async def reset_confirm(payload:PasswordResetConfirm,request:Request,db:AsyncSession=Depends(get_db)):
    row=await db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash==_hash_token(payload.token),PasswordResetToken.used_at.is_(None),PasswordResetToken.expires_at>=_now()))
    if not row: raise HTTPException(400,"Reset token is invalid or expired")
    user=await db.get(User,row.user_id); user.password_hash=hash_password(payload.new_password); row.used_at=_now()
    rows=await db.scalars(select(AuthSession).where(AuthSession.user_id==user.id,AuthSession.revoked_at.is_(None)))
    for s in rows.all(): s.revoked_at=_now()
    await record_audit(db,request,"auth.password_reset_completed","user",user.id,None,actor=user.email); await db.commit(); return {"reset":True}
@router.post("/invitations/accept")
async def accept_invitation(payload:InvitationAccept,request:Request,db:AsyncSession=Depends(get_db)):
    row=await db.scalar(select(AuthInvitation).where(AuthInvitation.token_hash==_hash_token(payload.token),AuthInvitation.accepted_at.is_(None),AuthInvitation.expires_at>=_now()))
    if not row: raise HTTPException(400,"Invitation is invalid or expired")
    user=await db.scalar(select(User).where(User.email==row.email))
    if user and await db.scalar(select(WorkspaceMember).where(WorkspaceMember.user_id==user.id,WorkspaceMember.workspace_id==row.workspace_id)): raise HTTPException(409,"Invitation has already been accepted")
    if not user: user=User(email=row.email,display_name=row.display_name,password_hash=hash_password(payload.password),email_verified=False,is_active=True); db.add(user); await db.flush()
    else: user.password_hash=hash_password(payload.password); user.is_active=True
    member=WorkspaceMember(workspace_id=row.workspace_id,user_id=user.id,role=row.role); db.add(member); row.accepted_at=_now()
    await record_audit(db,request,"auth.invitation_accepted","auth_invitation",row.id,{"email":row.email,"role":row.role},actor=row.email); await db.commit()
    return {"accepted":True,"workspace_id":row.workspace_id,"email":row.email}
@router.post("/email/verify")
async def verify_email(payload:VerifyEmailRequest,request:Request,db:AsyncSession=Depends(get_db)):
    row=await db.scalar(select(EmailVerificationToken).where(EmailVerificationToken.token_hash==_hash_token(payload.token),EmailVerificationToken.used_at.is_(None),EmailVerificationToken.expires_at>=_now()))
    if not row: raise HTTPException(400,"Verification token is invalid or expired")
    user=await db.get(User,row.user_id); user.email_verified=True; row.used_at=_now(); await record_audit(db,request,"auth.email_verified","user",user.id,None,actor=user.email); await db.commit(); return {"verified":True}