from __future__ import annotations

from enum import StrEnum
from fastapi import Header, HTTPException

class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_LEAD = "security_lead"
    ANALYST = "analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"

PERMISSIONS = {
    Role.OWNER: {"*"},
    Role.ADMIN: {"workspace:manage", "users:manage", "scan:create", "scan:view", "scan:cancel", "finding:view", "finding:edit", "finding:assign", "finding:close", "report:create", "report:export", "audit:view"},
    Role.SECURITY_LEAD: {"scan:create", "scan:view", "scan:cancel", "finding:view", "finding:edit", "finding:assign", "finding:close", "report:create", "report:export", "audit:view"},
    Role.ANALYST: {"scan:create", "scan:view", "finding:view", "finding:edit", "finding:assign", "report:create", "report:export"},
    Role.DEVELOPER: {"scan:view", "finding:view", "finding:edit"},
    Role.VIEWER: {"scan:view", "finding:view", "report:export"},
}

def require_permission(permission: str):
    async def dependency(x_phantom_role: str = Header(default=Role.VIEWER, alias="X-PHANTOM-Role")):
        try:
            role = Role(x_phantom_role.lower())
        except ValueError:
            raise HTTPException(status_code=403, detail="Unknown PHANTOM role")
        allowed = PERMISSIONS[role]
        if "*" not in allowed and permission not in allowed:
            raise HTTPException(status_code=403, detail=f"Role '{role}' cannot perform '{permission}'")
        return role
    return dependency
