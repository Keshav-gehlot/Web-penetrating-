from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from ..auth import Principal, current_principal

router = APIRouter(prefix="/api/v1/workspaces", tags=["workspaces"])

# Workspace membership is intentionally represented as a small service contract first.
# A persistent membership table can replace this bootstrap registry without changing
# the API shape.
MEMBERS = {
    "default": {
        "admin@phantom.local": {"role": "owner", "name": "PHANTOM Administrator"},
    }
}

class MemberCreate(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    role: str = Field(pattern="^(owner|admin|security_lead|analyst|developer|viewer)$")
    name: str = Field(min_length=1, max_length=120)

@router.get("/current")
async def current_workspace(principal: Principal = Depends(current_principal)):
    members = MEMBERS.get(principal.workspace_id, {})
    return {"id": principal.workspace_id, "name": "PHANTOM Security Workspace", "actor": principal.actor, "role": principal.role, "members": len(members)}

@router.get("/current/members")
async def members(principal: Principal = Depends(current_principal)):
    return [{"email": email, **member} for email, member in MEMBERS.get(principal.workspace_id, {}).items()]

@router.post("/current/members")
async def add_member(payload: MemberCreate, principal: Principal = Depends(current_principal)):
    if principal.role not in {"owner", "admin"}: raise HTTPException(403, "Only workspace owners and administrators can manage members")
    workspace = MEMBERS.setdefault(principal.workspace_id, {})
    if payload.email.lower() in workspace: raise HTTPException(409, "Member already exists")
    workspace[payload.email.lower()] = {"role": payload.role, "name": payload.name}
    return {"email": payload.email.lower(), **workspace[payload.email.lower()]}
