from __future__ import annotations
from enum import StrEnum
from fastapi import Depends, HTTPException
from .auth import Principal, current_principal

class Role(StrEnum):
    OWNER="owner"; ADMIN="admin"; SECURITY_LEAD="security_lead"; ANALYST="analyst"; DEVELOPER="developer"; VIEWER="viewer"
PERMISSIONS={
    Role.OWNER:{"*"},
    Role.ADMIN:{"workspace:manage","users:manage","scan:create","scan:view","scan:cancel","finding:view","finding:edit","finding:assign","finding:close","report:create","report:export","audit:view"},
    Role.SECURITY_LEAD:{"scan:create","scan:view","scan:cancel","finding:view","finding:edit","finding:assign","finding:close","report:create","report:export","audit:view"},
    Role.ANALYST:{"scan:create","scan:view","finding:view","finding:edit","finding:assign","report:create","report:export"},
    Role.DEVELOPER:{"scan:view","finding:view","finding:edit"},
    Role.VIEWER:{"scan:view","finding:view","report:export"},
}
def require_permission(permission:str):
    async def dependency(principal:Principal=Depends(current_principal)):
        try: role=Role(principal.role.lower())
        except ValueError: raise HTTPException(403,"Unknown PHANTOM role")
        if "*" not in PERMISSIONS[role] and permission not in PERMISSIONS[role]: raise HTTPException(403,f"Role '{role}' cannot perform '{permission}'")
        return principal
    return dependency
