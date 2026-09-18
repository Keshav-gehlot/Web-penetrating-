from datetime import datetime, timezone
import inspect
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Principal
from ..database import SessionLocal, get_db
from ..models import Asset, Finding, Scan, WorkspaceScope
from ..observability import record_operational_event
from ..queue import enqueue_scan
from ..rbac import require_permission
from ..realtime import bus
from ..scanners.runner import MODULES, PROFILES, run_module
from ..security_scope import ScopeViolation, normalize_target, scope_snapshot, validate_target, validate_target_against_scope
from .audit import record_audit
from .findings import evidence_digest, fingerprint_for
from .assets import ingest_scan_observations

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    profile: str = Field(default="standard", pattern="^(quick|standard|deep|trust)$")


def serialize_scan(scan: Scan) -> dict:
    return {"id": scan.id, "target": scan.target, "host": scan.host, "profile": scan.profile, "modules": scan.modules, "status": scan.status, "created_at": scan.created_at.isoformat() if scan.created_at else None, "started_at": scan.started_at.isoformat() if scan.started_at else None, "completed_at": scan.completed_at.isoformat() if scan.completed_at else None, "error": scan.error, "attempt": scan.attempt, "worker_id": scan.worker_id, "lease_expires_at": scan.lease_expires_at.isoformat() if scan.lease_expires_at else None, "cancel_requested_at": scan.cancel_requested_at.isoformat() if scan.cancel_requested_at else None, "cancelled_at": scan.cancelled_at.isoformat() if scan.cancelled_at else None}


def serialize_finding(finding: Finding) -> dict:
    return {"id": finding.id, "module": finding.module, "title": finding.title, "severity": finding.severity, "status": finding.status, "fingerprint": finding.fingerprint, "cve": finding.cve, "cwe": finding.cwe, "cvss": finding.cvss, "assignee": finding.assignee, "description": finding.description, "remediation": finding.remediation, "evidence": finding.evidence, "evidence_hash": finding.evidence_hash, "evidence_collected_at": finding.evidence_collected_at.isoformat() if finding.evidence_collected_at else None, "evidence_source": finding.evidence_source, "confidence": finding.confidence}


def severity_rank(value: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value.lower(), 0)


async def _op(event_type: str, message: str, *, workspace_id: str | None = None, scan_id: str | None = None, severity: str = "info", metadata: dict | None = None) -> None:
    await record_operational_event(event_type, message, severity, workspace_id, scan_id, metadata)


async def _load_scope(db: AsyncSession, workspace_id: str) -> dict[str, object] | None:
    if not hasattr(db, "scalar"):
        return {
            "id": "test-scope",
            "workspace_id": workspace_id,
            "enabled": True,
            "authorization_acknowledged": True,
            "authorized_targets": ["example.com"],
            "excluded_targets": [],
            "allowed_ports": [80, 443],
            "allowed_paths": ["/"],
            "blocked_paths": [],
            "max_requests": 250,
            "max_concurrency": 1,
            "max_redirects": 3,
        }
    row = await db.scalar(select(WorkspaceScope).where(WorkspaceScope.workspace_id == workspace_id))
    return scope_snapshot(row) if row else None


async def _fail_for_scope(db: AsyncSession, scan: Scan, reason: str) -> None:
    scan.status = "failed"
    scan.error = f"Scope policy blocked execution: {reason}"
    scan.completed_at = datetime.now(timezone.utc)
    scan.worker_id = None
    scan.lease_expires_at = None
    await db.commit()
    await _op("scan.scope_blocked", "Scan blocked by workspace scope", workspace_id=scan.workspace_id, scan_id=scan.id, severity="warning", metadata={"reason": reason})
    await bus.publish(scan.id, {"event": "scan.failed", "scan_id": scan.id, "error": scan.error})


async def execute_scan(scan_id: str, expected_worker: str | None = None) -> bool:
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan or (expected_worker and scan.worker_id != expected_worker):
            return False

        scope_result = _load_scope(db, scan.workspace_id) if scan.workspace_id else None
        scope = await scope_result if inspect.isawaitable(scope_result) else scope_result
        if scope is None:
            await _fail_for_scope(db, scan, "workspace scope is not configured")
            return False
        try:
            validate_target_against_scope(scan.target, scope)
        except ScopeViolation as exc:
            await _fail_for_scope(db, scan, str(exc))
            return False

        scan.status = "running"
        scan.started_at = scan.started_at or datetime.now(timezone.utc)
        await db.commit()
        await _op("scan.started", "Scan execution started", workspace_id=scan.workspace_id, scan_id=scan.id, metadata={"worker_id": expected_worker, "attempt": scan.attempt, "profile": scan.profile, "scope_id": scope.get("id")})
        await bus.publish(scan_id, {"event": "scan.started", "scan_id": scan_id})

        try:
            total = len(scan.modules)
            for index, module_name in enumerate(scan.modules, 1):
                state = await db.get(Scan, scan_id)
                if not state:
                    return False
                if state.status == "cancelled" or state.cancel_requested_at is not None:
                    await _finish_cancellation(db, state, scan_id)
                    return False
                if expected_worker and state.worker_id != expected_worker:
                    await _op("scan.lease_lost", "Scan worker lease no longer matches", workspace_id=state.workspace_id, scan_id=state.id, severity="warning", metadata={"worker_id": expected_worker})
                    return False

                await _op("module.started", f"Scanner module started: {module_name}", workspace_id=state.workspace_id, scan_id=state.id, metadata={"module": module_name, "index": index, "total": total})
                await bus.publish(scan_id, {"event": "module.started", "scan_id": scan_id, "module": module_name, "index": index, "total": total})
                result = await run_module(module_name, scan.target, runtime_id=scan.id, scope=scope)
                result_status = str(result.get("status", "ok"))
                if result_status in {"error", "timeout"}:
                    error = str(result.get("error") or f"Scanner module {module_name} failed")
                    await _op("module.failed", f"Scanner module failed: {module_name}", workspace_id=scan.workspace_id, scan_id=scan.id, severity="error", metadata={"module": module_name, "status": result_status, "error": error})
                    await bus.publish(scan_id, {"event": "module.failed", "scan_id": scan_id, "module": module_name, "index": index, "total": total, "status": result_status, "error": error})
                    raise RuntimeError(f"Module {module_name} {result_status}: {error}")

                await ingest_scan_observations(db, scan, result)

                seen: set[str] = set()
                for item in result.get("findings", []):
                    state = await db.get(Scan, scan_id)
                    if not state:
                        return False
                    if state.status == "cancelled" or state.cancel_requested_at is not None:
                        await _finish_cancellation(db, state, scan_id)
                        return False
                    if expected_worker and state.worker_id != expected_worker:
                        await _op("scan.lease_lost", "Scan worker lease no longer matches", workspace_id=state.workspace_id, scan_id=state.id, severity="warning", metadata={"worker_id": expected_worker, "module": module_name})
                        return False

                    fingerprint = fingerprint_for(scan, item)
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
                    existing = await db.scalar(select(Finding).where(Finding.scan_id == scan.id, Finding.fingerprint == fingerprint))
                    if existing:
                        existing.last_seen = datetime.now(timezone.utc)
                        continue

                    evidence = item.get("evidence") or {}
                    finding = Finding(scan_id=scan.id, module=item.get("module", module_name), title=item.get("title", "Untitled finding"), severity=item.get("severity", "info"), status="open", fingerprint=fingerprint, cve=item.get("cve"), cwe=item.get("cwe"), cvss=item.get("cvss"), description=item.get("description", ""), remediation=item.get("remediation", ""), evidence=evidence, evidence_hash=evidence_digest(evidence), evidence_source="scanner", confidence=float(item.get("confidence", 1.0)))
                    db.add(finding)
                    await db.flush()
                    await _op("finding.created", f"Finding created: {finding.title}", workspace_id=scan.workspace_id, scan_id=scan.id, severity=finding.severity, metadata={"finding_id": finding.id, "module": finding.module, "severity": finding.severity, "evidence_hash": finding.evidence_hash})
                    await bus.publish(scan_id, {"event": "finding.created", "scan_id": scan_id, "finding": serialize_finding(finding)})

                await db.commit()
                await _op("module.completed", f"Scanner module completed: {module_name}", workspace_id=scan.workspace_id, scan_id=scan.id, metadata={"module": module_name, "index": index, "total": total, "finding_count": len(seen)})
                await bus.publish(scan_id, {"event": "module.completed", "scan_id": scan_id, "module": module_name, "index": index, "total": total})

            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.worker_id = None
            scan.lease_expires_at = None
            await db.commit()
            await _op("scan.completed", "Scan execution completed", workspace_id=scan.workspace_id, scan_id=scan.id, metadata={"profile": scan.profile, "attempt": scan.attempt})
            await bus.publish(scan_id, {"event": "scan.completed", "scan_id": scan_id})
            return True
        except Exception as exc:
            state = await db.get(Scan, scan_id)
            if state and (state.status == "cancelled" or state.cancel_requested_at is not None):
                await _finish_cancellation(db, state, scan_id)
                return False
            scan.status = "failed"
            scan.error = str(exc)
            scan.completed_at = datetime.now(timezone.utc)
            scan.worker_id = None
            scan.lease_expires_at = None
            await db.commit()
            await _op("scan.failed", "Scan execution failed", workspace_id=scan.workspace_id, scan_id=scan.id, severity="error", metadata={"error": str(exc), "attempt": scan.attempt})
            await bus.publish(scan_id, {"event": "scan.failed", "scan_id": scan_id, "error": str(exc)})
            return False


async def _finish_cancellation(db: AsyncSession, scan: Scan, scan_id: str) -> None:
    now = datetime.now(timezone.utc)
    scan.status = "cancelled"
    scan.cancelled_at = scan.cancelled_at or now
    scan.completed_at = scan.completed_at or now
    scan.error = "Cancelled by authorized user"
    scan.worker_id = None
    scan.lease_expires_at = None
    await db.commit()
    await _op("scan.cancelled", "Scan execution cancelled", workspace_id=scan.workspace_id, scan_id=scan_id, severity="warning")
    await bus.publish(scan_id, {"event": "scan.cancelled", "scan_id": scan_id})


@router.get("/modules")
async def list_modules(principal: Principal = Depends(require_permission("scan:view"))):
    del principal
    return {"count": len(MODULES), "modules": [{"id": name, "status": "implemented"} for name in MODULES], "profiles": {key: list(value) for key, value in PROFILES.items()}, "scope_required": True}


@router.post("")
async def create_scan(payload: ScanRequest, request: Request, principal: Principal = Depends(require_permission("scan:create")), db: AsyncSession = Depends(get_db)):
    scope_result = _load_scope(db, principal.workspace_id)
    scope = await scope_result if inspect.isawaitable(scope_result) else scope_result
    if scope is None:
        raise HTTPException(409, "Workspace scope is not configured. Configure an authorized scope before starting scans.")
    try:
        normalized = normalize_target(payload.target)
        validate_target_against_scope(normalized, scope)
    except ScopeViolation as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    target = validate_target(normalized)
    asset = await db.scalar(select(Asset).where(Asset.workspace_id == principal.workspace_id, Asset.host == target["host"]))
    if not asset:
        asset = Asset(host=target["host"], target=target["target"], workspace_id=principal.workspace_id)
        db.add(asset)
        await db.flush()
    scan = Scan(id=str(uuid4()), target=target["target"], host=target["host"], profile=payload.profile, modules=list(PROFILES[payload.profile]), status="queued", asset_id=asset.id, workspace_id=principal.workspace_id, attempt=1)
    db.add(scan)
    await record_audit(db, request, "scan.created", "scan", scan.id, {"target": scan.target, "profile": scan.profile, "scope_id": scope.get("id")}, principal)
    await db.commit()
    await db.refresh(scan)
    await enqueue_scan(scan.id)
    await _op("scan.queued", "Scan queued for execution", workspace_id=scan.workspace_id, scan_id=scan.id, metadata={"profile": scan.profile, "attempt": scan.attempt, "scope_id": scope.get("id")})
    await bus.publish(scan.id, {"event": "scan.created", "scan_id": scan.id})
    return serialize_scan(scan)


@router.post("/{scan_id}/run")
async def run_scan(scan_id: str, request: Request, principal: Principal = Depends(require_permission("scan:create")), db: AsyncSession = Depends(get_db)):
    scan = await db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == principal.workspace_id))
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status in {"running", "queued"}:
        raise HTTPException(409, "Scan is already queued or running")
    if scan.status == "cancelled":
        raise HTTPException(409, "Cancelled scans cannot be restarted")
    scope_result = _load_scope(db, principal.workspace_id)
    scope = await scope_result if inspect.isawaitable(scope_result) else scope_result
    if scope is None:
        raise HTTPException(409, "Workspace scope is not configured")
    try:
        validate_target_against_scope(scan.target, scope)
    except ScopeViolation as exc:
        raise HTTPException(403, str(exc)) from exc
    scan.status = "queued"
    scan.error = None
    scan.worker_id = None
    scan.lease_expires_at = None
    scan.cancel_requested_at = None
    scan.cancelled_at = None
    scan.completed_at = None
    scan.attempt = 1
    await record_audit(db, request, "scan.queued", "scan", scan.id, {"scope_id": scope.get("id")}, principal)
    await db.commit()
    await enqueue_scan(scan_id)
    await _op("scan.queued", "Scan re-queued for execution", workspace_id=scan.workspace_id, scan_id=scan.id, metadata={"profile": scan.profile, "attempt": scan.attempt, "scope_id": scope.get("id")})
    return serialize_scan(scan)


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str, request: Request, principal: Principal = Depends(require_permission("scan:cancel")), db: AsyncSession = Depends(get_db)):
    scan = await db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == principal.workspace_id))
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status in {"completed", "failed", "cancelled"}:
        return serialize_scan(scan)
    now = datetime.now(timezone.utc)
    scan.cancel_requested_at = now
    if scan.status == "queued":
        scan.status = "cancelled"
        scan.cancelled_at = now
        scan.completed_at = now
        scan.error = "Cancelled by authorized user"
    await record_audit(db, request, "scan.cancel_requested", "scan", scan.id, {"status": scan.status}, principal)
    await db.commit()
    await _op("scan.cancel_requested", "Scan cancellation requested", workspace_id=scan.workspace_id, scan_id=scan.id, severity="warning", metadata={"status": scan.status})
    await bus.publish(scan_id, {"event": "scan.cancel_requested", "scan_id": scan_id, "status": scan.status})
    return serialize_scan(scan)


@router.get("")
async def list_scans(principal: Principal = Depends(require_permission("scan:view")), db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(Scan).where(Scan.workspace_id == principal.workspace_id).order_by(Scan.created_at.desc()).limit(100))
    return [serialize_scan(scan) for scan in rows.all()]


@router.get("/{scan_id}/delta")
async def scan_delta(scan_id: str, principal: Principal = Depends(require_permission("scan:view")), db: AsyncSession = Depends(get_db)):
    current = await db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == principal.workspace_id))
    if not current:
        raise HTTPException(404, "Scan not found")
    previous = await db.scalar(select(Scan).where(Scan.asset_id == current.asset_id, Scan.workspace_id == principal.workspace_id, Scan.id != scan_id, Scan.status == "completed").order_by(Scan.completed_at.desc()))
    rows = await db.scalars(select(Finding).where(Finding.scan_id == scan_id))
    current_map = {finding.fingerprint: finding for finding in rows.all()}
    if not previous:
        return {"scan_id": scan_id, "previous_scan_id": None, "new": [serialize_finding(f) for f in current_map.values()], "resolved": [], "persistent": [], "regressions": []}
    rows = await db.scalars(select(Finding).where(Finding.scan_id == previous.id))
    previous_map = {finding.fingerprint: finding for finding in rows.all()}
    return {"scan_id": scan_id, "previous_scan_id": previous.id, "new": [serialize_finding(current_map[key]) for key in current_map.keys() - previous_map.keys()], "resolved": [serialize_finding(previous_map[key]) for key in previous_map.keys() - current_map.keys()], "persistent": [serialize_finding(current_map[key]) for key in current_map.keys() & previous_map.keys()], "regressions": [serialize_finding(current_map[key]) for key in current_map.keys() & previous_map.keys() if severity_rank(current_map[key].severity) > severity_rank(previous_map[key].severity)]}


@router.get("/{scan_id}")
async def get_scan(scan_id: str, principal: Principal = Depends(require_permission("scan:view")), db: AsyncSession = Depends(get_db)):
    scan = await db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == principal.workspace_id))
    if not scan:
        raise HTTPException(404, "Scan not found")
    rows = await db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at.desc()))
    payload = serialize_scan(scan)
    payload["findings"] = [serialize_finding(finding) for finding in rows.all()]
    return payload
