from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.audit import AuditEvent, record_audit
from ..auth import Principal
from ..database import get_db
from ..models import Asset, AssetHistory, AssetService, Finding, FindingNote, Scan
from ..rbac import require_permission

router = APIRouter(prefix="/api/v1/investigations", tags=["investigations"])


class NoteUpdate(BaseModel):
    note: str = Field(max_length=20000)


class RemediationUpdate(BaseModel):
    remediation: str = Field(max_length=20000)


def serialize_note(note: FindingNote) -> dict:
    return {
        "id": note.id,
        "author_id": note.author_id,
        "note": note.note,
        "created_at": note.created_at.isoformat() if note.created_at else None,
        "updated_at": note.updated_at.isoformat() if note.updated_at else None,
    }


def serialize_audit(event: AuditEvent) -> dict:
    return {
        "id": event.id,
        "actor": event.actor,
        "action": event.action,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "metadata": event.metadata_json,
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }


def payload_parts(evidence: dict | None) -> tuple[object, object]:
    evidence = evidence or {}
    request = evidence.get("request")
    response = evidence.get("response")
    if request is None:
        request = {
            key: evidence[key]
            for key in ("method", "url", "path", "headers", "body", "parameters")
            if key in evidence
        }
    if response is None:
        response = {
            key: evidence[key]
            for key in ("status", "status_code", "headers", "body", "length")
            if key in evidence
        }
    return request, response


@router.get("/{finding_id}")
async def investigation(
    finding_id: str,
    principal: Principal = Depends(require_permission("finding:view")),
    db: AsyncSession = Depends(get_db),
):
    finding = await db.scalar(
        select(Finding).join(Scan).where(
            Finding.id == finding_id,
            Scan.workspace_id == principal.workspace_id,
        )
    )
    if not finding:
        raise HTTPException(404, "Finding not found")

    scan = await db.get(Scan, finding.scan_id)
    asset = await db.scalar(
        select(Asset).where(
            Asset.id == scan.asset_id,
            Asset.workspace_id == principal.workspace_id,
        )
    ) if scan and scan.asset_id else None

    services: list[dict] = []
    asset_history: list[dict] = []
    if asset:
        service_rows = await db.scalars(
            select(AssetService).where(AssetService.asset_id == asset.id).order_by(AssetService.port)
        )
        services = [
            {
                "id": s.id,
                "port": s.port,
                "protocol": s.protocol,
                "service": s.service,
                "state": s.state,
                "first_seen_at": s.first_seen_at.isoformat() if s.first_seen_at else None,
                "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
            }
            for s in service_rows.all()
        ]
        history_rows = await db.scalars(
            select(AssetHistory)
            .where(
                AssetHistory.asset_id == asset.id,
                AssetHistory.workspace_id == principal.workspace_id,
            )
            .order_by(AssetHistory.created_at.desc())
            .limit(100)
        )
        asset_history = [
            {
                "id": h.id,
                "event_type": h.event_type,
                "scan_id": h.scan_id,
                "metadata": h.metadata_json,
                "created_at": h.created_at.isoformat() if h.created_at else None,
            }
            for h in history_rows.all()
        ]

    # Same fingerprint represents the same finding observed across scans.
    related_rows = await db.scalars(
        select(Finding)
        .join(Scan)
        .where(
            Finding.fingerprint == finding.fingerprint,
            Finding.id != finding.id,
            Scan.workspace_id == principal.workspace_id,
        )
        .order_by(Finding.last_seen.desc())
        .limit(100)
    )
    related_findings = [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        }
        for f in related_rows.all()
    ]

    related_assets: list[dict] = []
    if asset:
        # Keep the relationship workspace-scoped and explicit. For now the
        # finding's observed asset is the canonical related asset.
        related_assets = [{
            "id": asset.id,
            "host": asset.host,
            "target": asset.target,
            "type": asset.asset_type,
            "environment": asset.environment,
            "criticality": asset.criticality,
            "owner": asset.owner,
        }]

    note_rows = await db.scalars(
        select(FindingNote)
        .where(
            FindingNote.finding_id == finding.id,
            FindingNote.workspace_id == principal.workspace_id,
        )
        .order_by(FindingNote.created_at.desc())
        .limit(100)
    )
    notes = [serialize_note(n) for n in note_rows.all()]

    audit_rows = await db.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.workspace_id == principal.workspace_id,
            or_(
                AuditEvent.resource_id == finding.id,
                AuditEvent.resource_id == finding.scan_id,
                AuditEvent.resource_id == (asset.id if asset else None),
            ),
        )
        .order_by(AuditEvent.created_at.desc())
        .limit(150)
    )
    audit_history = [serialize_audit(event) for event in audit_rows.all()]

    request_payload, response_payload = payload_parts(finding.evidence)
    timeline = [
        {
            "id": f"finding-created-{finding.id}",
            "event": "finding_created",
            "actor": None,
            "at": finding.created_at.isoformat() if finding.created_at else None,
            "metadata": {"scan_id": finding.scan_id},
        },
        {
            "id": f"finding-first-seen-{finding.id}",
            "event": "finding_first_seen",
            "actor": None,
            "at": finding.first_seen.isoformat() if finding.first_seen else None,
            "metadata": {},
        },
        {
            "id": f"finding-last-seen-{finding.id}",
            "event": "finding_last_observed",
            "actor": None,
            "at": finding.last_seen.isoformat() if finding.last_seen else None,
            "metadata": {},
        },
    ]
    timeline.extend({
        "id": f"audit-{event['id']}",
        "event": event["action"],
        "actor": event["actor"],
        "at": event["created_at"],
        "metadata": event["metadata"],
    } for event in audit_history)
    timeline.extend({
        "id": f"asset-{event['id']}",
        "event": event["event_type"],
        "actor": None,
        "at": event["created_at"],
        "metadata": event["metadata"],
    } for event in asset_history)
    timeline.sort(key=lambda item: item["at"] or "", reverse=True)

    return {
        "finding": {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "module": finding.module,
            "title": finding.title,
            "severity": finding.severity,
            "status": finding.status,
            "cve": finding.cve,
            "cwe": finding.cwe,
            "cvss": finding.cvss,
            "assignee": finding.assignee,
            "description": finding.description,
            "remediation": finding.remediation,
            "evidence": finding.evidence,
            "evidence_hash": finding.evidence_hash,
            "evidence_collected_at": finding.evidence_collected_at.isoformat() if finding.evidence_collected_at else None,
            "evidence_source": finding.evidence_source,
            "confidence": finding.confidence,
        },
        "target": {
            "host": scan.host if scan else "",
            "target": scan.target if scan else "",
            "profile": scan.profile if scan else "",
        },
        "asset": (
            {
                "id": asset.id,
                "host": asset.host,
                "addresses": asset.addresses,
                "type": asset.asset_type,
                "environment": asset.environment,
                "criticality": asset.criticality,
                "owner": asset.owner,
                "services": services,
                "history": asset_history,
            }
            if asset else None
        ),
        "related_findings": related_findings,
        "related_assets": related_assets,
        "notes": notes,
        "timeline": timeline,
        "audit_history": audit_history,
        "requests": [{"source": "finding.evidence", "payload": request_payload}],
        "responses": [{"source": "finding.evidence", "payload": response_payload}],
    }


@router.post("/{finding_id}/notes")
async def add_note(
    finding_id: str,
    payload: NoteUpdate,
    request: Request,
    principal: Principal = Depends(require_permission("finding:edit")),
    db: AsyncSession = Depends(get_db),
):
    finding = await db.scalar(
        select(Finding).join(Scan).where(
            Finding.id == finding_id,
            Scan.workspace_id == principal.workspace_id,
        )
    )
    if not finding:
        raise HTTPException(404, "Finding not found")

    now = datetime.now(timezone.utc)
    note = FindingNote(
        id=str(uuid4()),
        finding_id=finding.id,
        workspace_id=principal.workspace_id,
        author_id=principal.user_id,
        note=payload.note,
        created_at=now,
        updated_at=now,
    )
    db.add(note)
    await record_audit(
        db, request, "finding.note_created", "finding", finding.id,
        {"note_id": note.id, "length": len(payload.note)}, principal
    )
    await db.commit()
    await db.refresh(note)
    return {"finding_id": finding_id, "saved": True, "note": serialize_note(note)}


@router.patch("/{finding_id}/notes")
async def save_note_compat(
    finding_id: str,
    payload: NoteUpdate,
    request: Request,
    principal: Principal = Depends(require_permission("finding:edit")),
    db: AsyncSession = Depends(get_db),
):
    # Keep the existing client contract while changing persistence semantics
    # from destructive overwrite to append-only investigation history.
    return await add_note(finding_id, payload, request, principal, db)


@router.patch("/{finding_id}/remediation")
async def update_remediation(
    finding_id: str,
    payload: RemediationUpdate,
    request: Request,
    principal: Principal = Depends(require_permission("finding:edit")),
    db: AsyncSession = Depends(get_db),
):
    finding = await db.scalar(
        select(Finding).join(Scan).where(
            Finding.id == finding_id,
            Scan.workspace_id == principal.workspace_id,
        )
    )
    if not finding:
        raise HTTPException(404, "Finding not found")
    previous = finding.remediation
    finding.remediation = payload.remediation
    await record_audit(
        db, request, "finding.remediation_updated", "finding", finding.id,
        {"changed": previous != payload.remediation}, principal
    )
    await db.commit()
    return {"finding_id": finding_id, "remediation": finding.remediation}


@router.get("/{finding_id}/audit")
async def investigation_audit(
    finding_id: str,
    principal: Principal = Depends(require_permission("audit:view")),
    db: AsyncSession = Depends(get_db),
):
    finding = await db.scalar(
        select(Finding).join(Scan).where(
            Finding.id == finding_id,
            Scan.workspace_id == principal.workspace_id,
        )
    )
    if not finding:
        raise HTTPException(404, "Finding not found")
    rows = await db.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.workspace_id == principal.workspace_id,
            AuditEvent.resource_id == finding.id,
        )
        .order_by(AuditEvent.created_at.desc())
        .limit(250)
    )
    return [serialize_audit(event) for event in rows.all()]
