from __future__ import annotations
import hashlib,hmac
from dataclasses import dataclass
from datetime import datetime,timedelta,timezone
from fastapi import Header,HTTPException
from pydantic import BaseModel,Field
from .config import settings
@dataclass(frozen=True)
class Principal:
    actor:str; role:str; workspace_id:str; user_id:str|None=None
class LoginRequest(BaseModel):
    email:str=Field(min_length=3,max_length=255); password:str=Field(min_length=8,max_length=256); workspace_id:str=Field(default="default",min_length=1,max_length=100)
def _sign(payload:str)->str:return hmac.new(settings.AUTH_SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest()
def issue_token(actor:str,role:str,workspace_id:str,user_id:str|None=None,hours:int|None=None)->str:
    expires=int((datetime.now(timezone.utc)+timedelta(hours=hours if hours is not None else settings.SESSION_HOURS)).timestamp());uid=user_id or ""
    payload=f"{actor}|{role}|{workspace_id}|{uid}|{expires}";return f"{payload}|{_sign(payload)}"
def principal_from_token(token:str)->Principal:
    p=token.split("|")
    if len(p)!=6:raise HTTPException(401,"Invalid authentication token")
    actor,role,workspace_id,user_id,expiry,signature=p;payload="|".join(p[:5])
    try:valid=int(expiry)>=int(datetime.now(timezone.utc).timestamp())
    except ValueError:valid=False
    if not valid or not hmac.compare_digest(signature,_sign(payload)):raise HTTPException(401,"Authentication token expired or invalid")
    return Principal(actor,role,workspace_id,user_id or None)
async def current_principal(authorization:str|None=Header(default=None))->Principal:
    if not authorization or not authorization.lower().startswith("bearer "):raise HTTPException(401,"Authentication required")
    return principal_from_token(authorization[7:].strip())
