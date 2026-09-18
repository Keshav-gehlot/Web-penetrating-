from __future__ import annotations

from datetime import datetime, timezone

from uuid import uuid4

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
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



@router.post("/import")
async def import_assets(payload: dict, request: Request, principal: Principal = Depends(require_permission("workspace:manage")), db: AsyncSession = Depends(get_db)):
    rows = payload.get("assets")
    if not isinstance(rows, list) or len(rows) > 250:
        raise HTTPException(400, "assets must be a list containing at most 250 records")
    scope_row = await db.scalar(select(WorkspaceScope).where(WorkspaceScope.workspace_id == principal.workspace_id))
    if scope_row is None: raise HTTPException(409, "Workspace scope is not configured.")
    scope = scope_snapshot(scope_row)
    created = updated = skipped = 0
    for raw in rows:
        if not isinstance(raw, dict) or not raw.get("target"): skipped += 1; continue
        try:
            normalized = normalize_target(str(raw["target"]))
            validate_target_against_scope(normalized, scope)
            target = validate_target(normalized)
            asset_type = str(raw.get("asset_type", "web")); environment = str(raw.get("environment", "unknown"))
            criticality = str(raw.get("criticality", "medium")); status = str(raw.get("status", "active"))
            _validate_metadata(asset_type, environment, criticality, status)
        except (ScopeViolation, ValueError, HTTPException):
            skipped += 1; continue
        asset = await db.scalar(select(Asset).where(Asset.workspace_id == principal.workspace_id, Asset.host == target["host"]))
        if asset:
            asset.target = target["target"]; asset.last_seen_at = datetime.now(timezone.utc); updated += 1
            await _history(db, asset, "asset.imported", {"mode": "updated"})
        else:
            now = datetime.now(timezone.utc)
            asset = Asset(id=str(uuid4()), host=target["host"], target=target["target"], workspace_id=principal.workspace_id,
                addresses=public_addresses(target["host"]), asset_type=asset_type, environment=environment,
                criticality=criticality, owner=raw.get("owner"), tags=sorted({str(x).strip() for x in raw.get("tags", []) if str(x).strip()})[:30],
                notes=str(raw.get("notes", "")).strip(), status=status, last_seen_at=now)
            db.add(asset); await db.flush(); await _history(db, asset, "asset.imported", {"mode": "created"}); created += 1
    await record_audit(db, request, "asset.imported", "asset_inventory", None, {"created": created, "updated": updated, "skipped": skipped}, principal)
    await db.commit()
    return {"created": created, "updated": updated, "skipped": skipped, "processed": len(rows)}


@router.post("/import.csv")
async def import_assets_csv(request: Request, csv_text: str = Body(..., media_type="text/csv"), principal: Principal = Depends(require_permission("workspace:manage")), db: AsyncSession = Depends(get_db)):
    import csv, io
    try:
        rows = list(csv.DictReader(io.StringIO(csv_text)))
    except csv.Error as exc:
        raise HTTPException(400, f"Invalid CSV: {exc}") from exc
    assets = []
    for row in rows:
        assets.append({"target": row.get("target") or row.get("host"), "asset_type": row.get("type", "web"),
                       "environment": row.get("environment", "unknown"), "criticality": row.get("criticality", "medium"),
                       "owner": row.get("owner") or None, "status": row.get("status", "active"),
                       "tags": [x for x in (row.get("tags") or "").split("|") if x], "notes": row.get("notes", "")})
    return await import_assets({"assets": assets}, request, principal, db)


@router.get("/export.csv")
async def export_assets(request: Request, principal: Principal = Depends(require_permission("scan:view")), db: AsyncSession = Depends(get_db)):
    import csv, io
    rows = (await db.scalars(select(Asset).where(Asset.workspace_id == principal.workspace_id).order_by(Asset.host))).all()
    out = io.StringIO(); writer = csv.writer(out)
    writer.writerow(["id", "host", "target", "type", "environment", "criticality", "owner", "status", "tags", "addresses"])
    for a in rows:
        writer.writerow([a.id, a.host, a.target, a.asset_type, a.environment, a.criticality, a.owner or "", a.status, "|".join(a.tags or []), "|".join(a.addresses or [])])
    await record_audit(db, request, "asset.exported", "asset_inventory", None, {"count": len(rows)}, principal); await db.commit()
    return Response(content=out.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=phantom-assets.csv"})


@router.post("/bulk")
async def bulk_assets(payload: dict, request: Request, principal: Principal = Depends(require_permission("workspace:manage")), db: AsyncSession = Depends(get_db)):
    ids = list(dict.fromkeys(str(x) for x in payload.get("asset_ids", [])))[:250]
    action = str(payload.get("action", ""))
    if not ids or action not in {"activate", "deactivate", "delete"}: raise HTTPException(400, "Provide asset_ids and action: activate, deactivate, or delete")
    rows = (await db.scalars(select(Asset).where(Asset.workspace_id == principal.workspace_id, Asset.id.in_(ids)))).all()
    if len(rows) != len(ids): raise HTTPException(404, "One or more assets were not found in this workspace")
    for asset in rows:
        if action == "delete":
            await _history(db, asset, "asset.deleted", {"host": asset.host, "bulk": True}); await record_audit(db, request, "asset.deleted", "asset", asset.id, {"host": asset.host, "bulk": True}, principal); await db.delete(asset)
        else:
            asset.status = "active" if action == "activate" else "inactive"
            await _history(db, asset, "lifecycle.changed", {"status": asset.status, "bulk": True})
            await record_audit(db, request, "asset.updated", "asset", asset.id, {"status": asset.status, "bulk": True}, principal)
    await db.commit()
    return {"updated": len(rows), "action": action}


@router.get("/{asset_id}/findings")
async def asset_findings(asset_id: str, principal: Principal = Depends(require_permission("finding:view")), db: AsyncSession = Depends(get_db)):
    asset = await db.scalar(select(Asset).where(Asset.id == asset_id, Asset.workspace_id == principal.workspace_id))
    if not asset: raise HTTPException(404, "Asset not found")
    rows = (await db.scalars(select(Finding).join(Scan).where(Scan.asset_id == asset.id, Scan.workspace_id == principal.workspace_id).order_by(Finding.last_seen.desc()).limit(500))).all()
    return [{"id": f.id, "scan_id": f.scan_id, "module": f.module, "title": f.title, "severity": f.severity, "status": f.status,
             "fingerprint": f.fingerprint, "cve": f.cve, "cwe": f.cwe, "cvss": f.cvss, "confidence": f.confidence,
             "first_seen": f.first_seen.isoformat() if f.first_seen else None, "last_seen": f.last_seen.isoformat() if f.last_seen else None} for f in rows]


@router.get("/{asset_id}/history")
async def asset_history(asset_id: str, principal: Principal = Depends(require_permission("scan:view")), db: AsyncSession = Depends(get_db)):
    asset = await db.scalar(select(Asset).where(Asset.id == asset_id, Asset.workspace_id == principal.workspace_id))
    if not asset: raise HTTPException(404, "Asset not found")
    rows = (await db.scalars(select(AssetHistory).where(AssetHistory.asset_id == asset.id, AssetHistory.workspace_id == principal.workspace_id).order_by(AssetHistory.created_at.desc()).limit(250))).all()
    return [{"id": h.id, "event_type": h.event_type, "scan_id": h.scan_id, "metadata": h.metadata_json, "created_at": h.created_at.isoformat() if h.created_at else None} for h in rows]


@router.get("/{asset_id}/services")
async def asset_services(asset_id: str, principal: Principal = Depends(require_permission("scan:view")), db: AsyncSession = Depends(get_db)):
    asset = await db.scalar(select(Asset).where(Asset.id == asset_id, Asset.workspace_id == principal.workspace_id))
    if not asset: raise HTTPException(404, "Asset not found")
    rows = (await db.scalars(select(AssetService).where(AssetService.asset_id == asset.id).order_by(AssetService.port))).all()
    return [{"id": s.id, "port": s.port, "protocol": s.protocol, "service": s.service, "state": s.state,
             "first_seen_at": s.first_seen_at.isoformat() if s.first_seen_at else None, "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None} for s in rows]

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
    previous = set(asset.addresses or [])
    asset.addresses, asset.last_resolved_at, asset.last_seen_at = addresses, now, now
    if set(addresses) != previous: await _history(db, asset, 'network.addresses_changed', {'previous': sorted(previous), 'current': sorted(addresses)})
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
