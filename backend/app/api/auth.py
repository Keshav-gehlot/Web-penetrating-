from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from ..auth import LoginRequest, authenticate, issue_token

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    actor: str
    role: str
    workspace_id: str

@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest):
    principal = authenticate(payload.email, payload.password, payload.workspace_id)
    if not principal:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return LoginResponse(access_token=issue_token(principal.actor, principal.role, principal.workspace_id), actor=principal.actor, role=principal.role, workspace_id=principal.workspace_id)
