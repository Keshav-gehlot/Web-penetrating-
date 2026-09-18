from __future__ import annotations
from enum import StrEnum

from fastapi import Depends, HTTPException

from .auth import Principal, current_principal


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_LEAD = "security_lead"
    ANALYST = "analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"


# Higher number means more privilege. This hierarchy is used only for
# administrative role-assignment safeguards; endpoint permissions remain the
# authoritative access-control mechanism.
ROLE_LEVEL = {
    Role.OWNER: 6,
    Role.ADMIN: 5,
    Role.SECURITY_LEAD: 4,
    Role.ANALYST: 3,
    Role.DEVELOPER: 2,
    Role.VIEWER: 1,
}

PERMISSIONS: dict[Role, set[str]] = {
    Role.OWNER: {"*"},
    Role.ADMIN: {
        "workspace:manage", "scope:approve", "users:manage",
        "scan:create", "scan:view", "scan:cancel",
        "finding:view", "finding:edit", "finding:assign", "finding:close",
        "report:create", "report:export", "audit:view",
    },
    Role.SECURITY_LEAD: {
        "scan:create", "scan:view", "scan:cancel",
        "finding:view", "finding:edit", "finding:assign", "finding:close",
        "report:create", "report:export", "audit:view",
    },
    Role.ANALYST: {
        "scan:create", "scan:view",
        "finding:view", "finding:edit", "finding:assign",
        "report:create", "report:export",
    },
    Role.DEVELOPER: {"scan:view", "finding:view", "finding:edit"},
    Role.VIEWER: {"scan:view", "finding:view", "report:export"},
}

ALL_PERMISSIONS = sorted({
    permission
    for permissions in PERMISSIONS.values()
    for permission in permissions
    if permission != "*"
})


def role_permissions(role: str) -> set[str]:
    try:
        normalized = Role(role.lower())
    except ValueError as exc:
        raise HTTPException(403, "Unknown PHANTOM role") from exc
    permissions = PERMISSIONS[normalized]
    return set(ALL_PERMISSIONS) if "*" in permissions else set(permissions)


def can_assign_role(actor_role: str, target_role: str) -> bool:
    try:
        actor = Role(actor_role.lower())
        target = Role(target_role.lower())
    except ValueError:
        return False
    # Owners may delegate any defined role. Everyone else may only grant a
    # role at or below their own level, preventing vertical privilege
    # escalation through the role-management endpoint.
    return actor == Role.OWNER or ROLE_LEVEL[target] <= ROLE_LEVEL[actor]


def require_permission(permission: str):
    async def dependency(principal: Principal = Depends(current_principal)):
        permissions = role_permissions(principal.role)
        if permission not in permissions:
            raise HTTPException(403, f"Role '{principal.role}' cannot perform '{permission}'")
        return principal
    return dependency
