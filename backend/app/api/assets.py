from __future__ import annotations

from datetime import datetime, timezone

from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Principal
from ..database import get_db
from ..models import Asset, AssetHistory, AssetService, Finding, Scan, WorkspaceScope
from ..rbac import require_permission
from ..security_scope import ScopeViolation, normalize_target, scope_snapshot, validate_target, validate_target_against_scope
from .audit import record_audit

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


class AssetCreate(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    asset_type: str = Field(default="web", max_length=32)
    environment: str = Field(default="unknown", max_length=32)
    criticality: str = Field(default="medium", max_length=16)
    owner: str | None = Field(default=None, max_length=255)
    tags: list[str] = Field(default_factory=list, max_length=30)
    notes: str = Field(default="", max_length=5000)


class AssetUpdate(BaseModel):
    target: str | None = Field(default=None, min_length=1, max_length=2048)
    asset_type: str | None = Field(default=None, max_length=32)
    environment: str | None = Field(default=None, max_length=32)
    criticality: str | None = Field(default=None, max_length=16)
    owner: str | None = Field(default=None, max_length=255)
    tags: list[str] | None = Field(default=None, max_length=30)
    notes: str | None = Field(default=None, max_length=5000)
    status: str | None = Field(default=None, max_length=16)


ASSET_TYPES = {"web", "api", "domain", "host", "service"}
ENVIRONMENTS = {"production", "staging", "development", "internal", "unknown"}
CRITICALITIES = {"critical", "high", "medium", "low"}
STATUSES = {"active", "inactive"}
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _validate_metadata(asset_type: str, environment: str, criticality: str, status: str) -> None:
    if asset_type not in ASSET_TYPES or environment not in ENVIRONMENTS or criticality not in CRITICALITIES or status not in STATUSES:
        raise HTTPException(400, "Invalid asset metadata value")


def public_addresses(host: str) -> list[str]:
    from ..security_scope import resolve_public_host
    try:
        return resolve_public_host(host)
    except HTTPException:
        return []



async def _history(db, asset, event_type: str, metadata: dict | None = None, scan_id: str | None = None):
    db.add(AssetHistory(id=str(uuid4()), asset_id=asset.id, workspace_id=asset.workspace_id, scan_id=scan_id, event_type=event_type, metadata_json=metadata or {}))

async def ingest_scan_observations(db, scan: Scan, result: dict) -> None:
    asset = await db.scalar(select(Asset).where(Asset.id == scan.asset_id, Asset.workspace_id == scan.workspace_id))
    if not asset: return
    now = datetime.now(timezone.utc)
    changed = False
    for row in result.get('ports', []) or []:
        try: port = int(row.get('port'))
        except (TypeError, ValueError): continue
        protocol = str(row.get('protocol', 'tcp')).lower()
        state = str(row.get('state', 'open')).lower()
        service = row.get('service')
        existing = await db.scalar(select(AssetService).where(AssetService.asset_id == asset.id, AssetService.port == port, AssetService.protocol == protocol))
        if existing:
            if existing.state != state or existing.service != service:
                changed = True; existing.state, existing.service, existing.last_seen_at, existing.source_scan_id = state, service, now, scan.id
        else:
            changed = True
            db.add(AssetService(id=str(uuid4()), asset_id=asset.id, port=port, protocol=protocol, service=service, state=state, source_scan_id=scan.id, first_seen_at=now, last_seen_at=now))
    subdomains = result.get('subdomains', []) or []
    if subdomains: await _history(db, asset, 'discovery.subdomains', {'count': len(subdomains), 'hosts': [x.get('host') for x in subdomains[:100]]}, scan.id); changed = True
    technologies = result.get('technologies', []) or []
    if technologies: await _history(db, asset, 'discovery.technology', {'technologies': technologies[:100]}, scan.id); changed = True
    if changed:
        asset.last_seen_at = now
        await _history(db, asset, 'discovery.updated', {'module': result.get('module'), 'ports': len(result.get('ports', []) or [])}, scan.id)

async def serialize(asset, db, include_scans=False):
    scans = (await db.scalars(select(Scan).where(Scan.asset_id == asset.id).order_by(Scan.created_at.desc()).limit(10 if include_scans else 1))).all()
    findings = (await db.scalars(select(Finding).join(Scan).where(Scan.asset_id == asset.id))).all()
    risk = max((f.severity for f in findings), key=lambda x: RANK.get(x, 0), default="info")
    addresses = list(asset.addresses or [])
    if not addresses:
        addresses = public_addresses(asset.host)
    result = {
        "id": asset.id, "host": asset.host, "target": asset.target, "addresses": addresses,
        "type": asset.asset_type, "environment": asset.environment, "criticality": asset.criticality,
        "owner": asset.owner, "tags": list(asset.tags or []), "notes": asset.notes or "",
        "status": asset.status, "risk": risk, "finding_count": len(findings), "scan_count": len(scans),
        "last_scan": scans[0].completed_at.isoformat() if scans and scans[0].completed_at else None,
        "last_scan_status": scans[0].status if scans else None,
        "last_seen_at": asset.last_seen_at.isoformat() if asset.last_seen_at else None,
        "last_resolved_at": asset.last_resolved_at.isoformat() if asset.last_resolved_at else None,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
    }
    services = (await db.scalars(select(AssetService).where(AssetService.asset_id == asset.id).order_by(AssetService.port))).all()
    result['services'] = [{'port': s.port, 'protocol': s.protocol, 'service': s.service, 'state': s.state, 'first_seen_at': s.first_seen_at.isoformat() if s.first_seen_at else None, 'last_seen_at': s.last_seen_at.isoformat() if s.last_seen_at else None} for s in services]
    if include_scans:
        history = (await db.scalars(select(AssetHistory).where(AssetHistory.asset_id == asset.id).order_by(AssetHistory.created_at.desc()).limit(100))).all()
        result['history'] = [{'id': h.id, 'event_type': h.event_type, 'scan_id': h.scan_id, 'metadata': h.metadata_json, 'created_at': h.created_at.isoformat() if h.created_at else None} for h in history]
        result["recent_scans"] = [{"id": s.id, "profile": s.profile, "status": s.status,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None} for s in scans]
    return result


@router.get("")
async def list_assets(principal: Principal = Depends(require_permission("scan:view")), db: AsyncSession = Depends(get_db),
                      status: str | None = None, environment: str | None = None,
                      criticality: str | None = None, q: str | None = None):
    query = select(Asset).where(Asset.workspace_id == principal.workspace_id)
    if status:
        if status not in STATUSES: raise HTTPException(400, "Invalid asset status")
        query = query.where(Asset.status == status)
    if environment:
        if environment not in ENVIRONMENTS: raise HTTPException(400, "Invalid asset environment")
        query = query.where(Asset.environment == environment)
    if criticality:
        if criticality not in CRITICALITIES: raise HTTPException(400, "Invalid asset criticality")
        query = query.where(Asset.criticality == criticality)
    if q and q.strip():
        pattern = f"%{q.strip()}%"
        query = query.where((Asset.host.ilike(pattern)) | (Asset.target.ilike(pattern)) | (Asset.owner.ilike(pattern)))
    rows = await db.scalars(query.order_by(Asset.created_at.desc()).limit(500))
    return [await serialize(a, db) for a in rows.all()]


@router.get("/{asset_id}")
async def get_asset(asset_id: str, principal: Principal = Depends(require_permission("scan:view")), db: AsyncSession = Depends(get_db)):
    asset = await db.scalar(select(Asset).where(Asset.id == asset_id, Asset.workspace_id == principal.workspace_id))
    if not asset: raise HTTPException(404, "Asset not found")
    return await serialize(asset, db, True)


@router.post("")
async def create_asset(payload: AssetCreate, request: Request, principal: Principal = Depends(require_permission("scan:create")), db: AsyncSession = Depends(get_db)):
    _validate_metadata(payload.asset_type, payload.environment, payload.criticality, "active")
    scope_row = await db.scalar(select(WorkspaceScope).where(WorkspaceScope.workspace_id == principal.workspace_id))
    if scope_row is None: raise HTTPException(409, "Workspace scope is not configured. Configure an authorized scope before onboarding assets.")
    scope = scope_snapshot(scope_row)
    try:
        normalized = normalize_target(payload.target)
        validate_target_against_scope(normalized, scope)
        target = validate_target(normalized)
    except ScopeViolation as exc: raise HTTPException(403, str(exc)) from exc
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc
    asset = await db.scalar(select(Asset).where(Asset.workspace_id == principal.workspace_id, Asset.host == target["host"]))
    if asset: return await serialize(asset, db)
    addresses = public_addresses(target["host"])
    now = datetime.now(timezone.utc)
    asset = Asset(id=str(uuid4()), host=target["host"], target=target["target"], workspace_id=principal.workspace_id,
        addresses=addresses, asset_type=payload.asset_type, environment=payload.environment,
        criticality=payload.criticality, owner=payload.owner.strip() if payload.owner else None,
        tags=sorted({x.strip() for x in payload.tags if x.strip()})[:30], notes=payload.notes.strip(),
        status="active", last_seen_at=now, last_resolved_at=now if addresses else None)
    db.add(asset); await db.flush()
    await _history(db, asset, "asset.created", {"host": asset.host})
    await record_audit(db, request, "asset.created", "asset", asset.id, {"host": asset.host, "scope_id": scope.get("id")}, principal)
    await db.commit()
    return await serialize(asset, db)


@router.patch("/{asset_id}")
async def update_asset(asset_id: str, payload: AssetUpdate, request: Request,
                       principal: Principal = Depends(require_permission("workspace:manage")), db: AsyncSession = Depends(get_db)):
    asset = await db.scalar(select(Asset).where(Asset.id == asset_id, Asset.workspace_id == principal.workspace_id))
    if not asset: raise HTTPException(404, "Asset not found")
    values = payload.model_dump(exclude_unset=True)
    next_values = {
        "asset_type": values.get("asset_type", asset.asset_type), "environment": values.get("environment", asset.environment),
        "criticality": values.get("criticality", asset.criticality), "status": values.get("status", asset.status)}
    _validate_metadata(**next_values)
    if "target" in values:
        scope_row = await db.scalar(select(WorkspaceScope).where(WorkspaceScope.workspace_id == principal.workspace_id))
        if scope_row is None: raise HTTPException(409, "Workspace scope is not configured.")
        try:
            normalized = normalize_target(values["target"])
            validate_target_against_scope(normalized, scope_snapshot(scope_row))
            target = validate_target(normalized)
        except ScopeViolation as exc: raise HTTPException(403, str(exc)) from exc
        except ValueError as exc: raise HTTPException(400, str(exc)) from exc
        duplicate = await db.scalar(select(Asset).where(Asset.workspace_id == principal.workspace_id, Asset.host == target["host"], Asset.id != asset.id))
        if duplicate: raise HTTPException(409, "Another asset already represents this host.")
        asset.host, asset.target = target["host"], target["target"]
        asset.addresses = public_addresses(asset.host)
        asset.last_resolved_at = datetime.now(timezone.utc) if asset.addresses else None
    asset.asset_type, asset.environment, asset.criticality, asset.status = next_values.values()
    if "owner" in values: asset.owner = values["owner"].strip() if values["owner"] else None
    if "tags" in values: asset.tags = sorted({x.strip() for x in values["tags"] if x.strip()})[:30]
    if "notes" in values: asset.notes = values["notes"].strip()
    asset.last_seen_at = datetime.now(timezone.utc)
    await _history(db, asset, "asset.updated", {"changed_fields": sorted(values)})
    await record_audit(db, request, "asset.updated", "asset", asset.id, {"host": asset.host, "changed_fields": sorted(values)}, principal)
    await db.commit()
    return await serialize(asset, db)


@router.post("/{asset_id}/resolve")
async def resolve_asset(asset_id: str, request: Request, principal: Principal = Depends(require_permission("scan:view")), db: AsyncSession = Depends(get_db)):
    asset = await db.scalar(select(Asset).where(Asset.id == asset_id, Asset.workspace_id == principal.workspace_id))
    if not asset: raise HTTPException(404, "Asset not found")
    addresses = public_addresses(asset.host)
    now = datetime.now(timezone.utc)
    asset.addresses, asset.last_resolved_at, asset.last_seen_at = addresses, now, now
    await record_audit(db, request, "asset.resolved", "asset", asset.id, {"address_count": len(addresses)}, principal)
    await db.commit()
    return await serialize(asset, db)


@router.delete("/{asset_id}")
async def delete_asset(
    asset_id: str,
    request: Request,
    principal: Principal = Depends(require_permission("workspace:manage")),
    db: AsyncSession = Depends(get_db),
):
    asset = await db.scalar(select(Asset).where(Asset.id == asset_id, Asset.workspace_id == principal.workspace_id))
    if not asset:
        raise HTTPException(404, "Asset not found")
    await _history(db, asset, "asset.deleted", {"host": asset.host})
    await record_audit(db, request, "asset.deleted", "asset", asset.id, {"host": asset.host}, principal)
    await db.delete(asset)
    await db.commit()
    return {"deleted": True}
