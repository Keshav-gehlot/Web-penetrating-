from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Principal
from ..config import settings
from ..database import get_db
from ..models import AuthInvitation, User, WorkspaceMember
from ..rbac import ROLE_LEVEL, Role, can_assign_role, require_permission
from ..security import hash_password
from .audit import record_audit

router = APIRouter(prefix="/api/v1/workspaces", tags=["workspaces"])


class MemberRoleUpdate(BaseModel):
    role: str = Field(pattern="^(owner|admin|security_lead|analyst|developer|viewer)$")


class InvitationCreate(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    role: str = Field(pattern="^(owner|admin|security_lead|analyst|developer|viewer)$")
    name: str = Field(min_length=1, max_length=120)


def _role(value: str) -> Role:
    try:
        return Role(value.lower())
    except ValueError as exc:
        raise HTTPException(400, "Invalid workspace role") from exc


async def _owner_count(db: AsyncSession, workspace_id: str) -> int:
    return int(
        await db.scalar(
            select(func.count())
            .select_from(WorkspaceMember)
            .where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.role == Role.OWNER.value,
            )
        )
        or 0
    )


def _assert_role_delegation(principal: Principal, target_role: str) -> Role:
    target = _role(target_role)
    if not can_assign_role(principal.role, target.value):
        raise HTTPException(
            403,
            f"Role '{principal.role}' cannot grant or assign '{target.value}'",
        )
    return target


@router.get("/current")
async def current(
    principal: Principal = Depends(require_permission("scan:view")),
    db: AsyncSession = Depends(get_db),
):
    count = await db.scalar(
        select(func.count())
        .select_from(WorkspaceMember)
        .where(WorkspaceMember.workspace_id == principal.workspace_id)
    ) or 0
    return {
        "id": principal.workspace_id,
        "name": "PHANTOM Security Workspace",
        "actor": principal.actor,
        "role": principal.role,
        "members": int(count),
    }


@router.get("/current/members")
async def members(
    principal: Principal = Depends(require_permission("users:manage")),
    db: AsyncSession = Depends(get_db),
):
    rows = await db.scalars(
        select(WorkspaceMember)
        .where(WorkspaceMember.workspace_id == principal.workspace_id)
        .order_by(WorkspaceMember.created_at.asc())
    )
    return [
        {
            "id": member.id,
            "email": member.user.email,
            "name": member.user.display_name,
            "role": member.role,
            "active": member.user.is_active,
        }
        for member in rows.all()
    ]


@router.post("/current/invitations")
async def invite_member(
    payload: InvitationCreate,
    request: Request,
    principal: Principal = Depends(require_permission("users:manage")),
    db: AsyncSession = Depends(get_db),
):
    target_role = _assert_role_delegation(principal, payload.role)
    email = payload.email.strip().lower()

    existing = await db.scalar(
        select(WorkspaceMember)
        .join(User)
        .where(
            WorkspaceMember.workspace_id == principal.workspace_id,
            User.email == email,
        )
    )
    if existing:
        raise HTTPException(409, "Member already exists")

    # An invitation is an authorization change too: apply the same hierarchy
    # guard before the invite is persisted.
    token = secrets.token_urlsafe(48)
    invitation = AuthInvitation(
        workspace_id=principal.workspace_id,
        email=email,
        display_name=payload.name,
        role=target_role.value,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        invited_by=principal.user_id,
    )
    db.add(invitation)
    await db.flush()
    await record_audit(
        db,
        request,
        "auth.invitation_created",
        "auth_invitation",
        invitation.id,
        {"email": email, "role": target_role.value},
        principal,
    )
    await db.commit()
    return {
        "id": invitation.id,
        "email": email,
        "role": target_role.value,
        "expires_at": invitation.expires_at.isoformat(),
        "invitation_token": token if settings.ENVIRONMENT != "production" else None,
    }


@router.post("/current/members")
async def add_member(
    payload: InvitationCreate,
    request: Request,
    principal: Principal = Depends(require_permission("users:manage")),
    db: AsyncSession = Depends(get_db),
):
    return await invite_member(payload, request, principal, db)


@router.patch("/current/members/{member_id}")
async def change_role(
    member_id: str,
    payload: MemberRoleUpdate,
    request: Request,
    principal: Principal = Depends(require_permission("users:manage")),
    db: AsyncSession = Depends(get_db),
):
    target_role = _assert_role_delegation(principal, payload.role)
    member = await db.get(WorkspaceMember, member_id)
    if not member or member.workspace_id != principal.workspace_id:
        raise HTTPException(404, "Member not found")

    old_role = _role(member.role)
    if old_role == target_role:
        return {"id": member.id, "role": member.role}

    if old_role == Role.OWNER and target_role != Role.OWNER:
        owners = await _owner_count(db, principal.workspace_id)
        if owners <= 1:
            raise HTTPException(409, "The workspace must retain at least one owner")

    # A non-owner cannot alter an owner because the hierarchy check above
    # rejects that target transition. Owners may manage any member.
    member.role = target_role.value
    await record_audit(
        db,
        request,
        "workspace.member_role_changed",
        "workspace_member",
        member.id,
        {"from": old_role.value, "to": target_role.value, "target_user_id": member.user_id},
        principal,
    )
    await db.commit()
    return {"id": member.id, "role": member.role}


@router.delete("/current/members/{member_id}")
async def remove_member(
    member_id: str,
    request: Request,
    principal: Principal = Depends(require_permission("users:manage")),
    db: AsyncSession = Depends(get_db),
):
    member = await db.get(WorkspaceMember, member_id)
    if not member or member.workspace_id != principal.workspace_id:
        raise HTTPException(404, "Member not found")

    target_role = _role(member.role)
    if not can_assign_role(principal.role, target_role.value):
        raise HTTPException(403, "You cannot remove a member with a higher privilege level")

    if target_role == Role.OWNER:
        owners = await _owner_count(db, principal.workspace_id)
        if owners <= 1:
            raise HTTPException(409, "The workspace must retain at least one owner")

    user = await db.get(User, member.user_id)
    member_id_value = member.id
    if user:
        user.is_active = False
    await db.delete(member)
    await record_audit(
        db,
        request,
        "workspace.member_removed",
        "workspace_member",
        member_id_value,
        {"target_user_id": member.user_id, "role": target_role.value},
        principal,
    )
    await db.commit()
    return {"removed": True}
