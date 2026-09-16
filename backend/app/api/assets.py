from __future__ import annotations
import ipaddress,socket
from urllib.parse import urlparse
from uuid import uuid4
from fastapi import APIRouter,Depends,HTTPException,Request
from pydantic import BaseModel,Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import Principal
from ..database import get_db
from ..main import validate_target
from ..models import Asset,Finding,Scan
from ..rbac import require_permission
from .audit import record_audit
router=APIRouter(prefix="/api/v1/assets",tags=["assets"])
class AssetCreate(BaseModel):target:str=Field(min_length=1,max_length=2048)
RANK={"info":0,"low":1,"medium":2,"high":3,"critical":4}
def public_addresses(host:str)->list[str]:
    try:addresses=sorted({x[4][0] for x in socket.getaddrinfo(host,None)})
    except socket.gaierror:return []
    return [a for a in addresses if not (lambda ip:ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)(ipaddress.ip_address(a))]
async def serialize(asset,db):
    scans=(await db.scalars(select(Scan).where(Scan.asset_id==asset.id).order_by(Scan.created_at.desc()).limit(1))).all();latest=scans[0] if scans else None
    findings=(await db.scalars(select(Finding).join(Scan).where(Scan.asset_id==asset.id))).all();risk=max((f.severity for f in findings),key=lambda x:RANK.get(x,0),default="info")
    return {"id":asset.id,"host":asset.host,"target":asset.target,"addresses":public_addresses(asset.host),"type":"Web target","risk":risk,"last_scan":latest.completed_at.isoformat() if latest and latest.completed_at else None,"last_scan_status":latest.status if latest else None,"created_at":asset.created_at.isoformat() if asset.created_at else None}
@router.get("")
async def list_assets(principal:Principal=Depends(require_permission("scan:view")),db:AsyncSession=Depends(get_db)):
    rows=await db.scalars(select(Asset).where(Asset.workspace_id==principal.workspace_id).order_by(Asset.created_at.desc()).limit(500));return [await serialize(a,db) for a in rows.all()]
@router.post("")
async def create_asset(payload:AssetCreate,request:Request,principal:Principal=Depends(require_permission("scan:create")),db:AsyncSession=Depends(get_db)):
    target=validate_target(payload.target);asset=await db.scalar(select(Asset).where(Asset.workspace_id==principal.workspace_id,Asset.host==target["host"]))
    if asset:return await serialize(asset,db)
    asset=Asset(id=str(uuid4()),host=target["host"],target=target["target"],workspace_id=principal.workspace_id);db.add(asset);await db.flush();await record_audit(db,request,"asset.created","asset",asset.id,{"host":asset.host},principal);await db.commit();return await serialize(asset,db)
@router.delete("/{asset_id}")
async def delete_asset(asset_id:str,request:Request,principal:Principal=Depends(require_permission("workspace:manage")),db:AsyncSession=Depends(get_db)):
    asset=await db.scalar(select(Asset).where(Asset.id==asset_id,Asset.workspace_id==principal.workspace_id))
    if not asset:raise HTTPException(404,"Asset not found")
    await record_audit(db,request,"asset.deleted","asset",asset.id,{"host":asset.host},principal);await db.delete(asset);await db.commit();return {"deleted":True}
