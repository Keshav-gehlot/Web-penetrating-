from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Principal
from ..database import get_db
from ..models import Asset, AssetHistory, AssetService, AssetTechnology, Finding, Scan
from ..rbac import require_permission

router = APIRouter(prefix="/api/v1/topology", tags=["topology"])

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _node(node_id: str, kind: str, label: str, **data) -> dict:
    return {"id": node_id, "type": kind, "label": label, **data}


def _edge(source: str, target: str, relation: str, **data) -> dict:
    return {"id": f"{relation}:{source}:{target}", "source": source, "target": target, "relation": relation, **data}


def _finding_matches_service(finding: Finding, service: AssetService) -> bool:
    evidence = finding.evidence or {}
    port = evidence.get("port")
    if port is None and isinstance(evidence.get("service"), dict):
        port = evidence["service"].get("port")
    try:
        return int(port) == service.port
    except (TypeError, ValueError):
        return False


def _finding_endpoint(finding: Finding) -> str | None:
    evidence = finding.evidence or {}
    for key in ("url", "path", "endpoint", "location", "action"):
        value = evidence.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _hostname(value: str) -> str | None:
    try:
        parsed = urlparse(value if "://" in value else f"https://{value}")
        return parsed.hostname
    except ValueError:
        return None


@router.get("")
async def get_topology(
    scan_id: str | None = None,
    delta: bool = False,
    q: str | None = None,
    node_type: str | None = None,
    severity: str | None = None,
    principal: Principal = Depends(require_permission("scan:view")),
    db: AsyncSession = Depends(get_db),
):
    assets = (await db.scalars(
        select(Asset).where(Asset.workspace_id == principal.workspace_id).order_by(Asset.host)
    )).all()

    asset_ids = {asset.id for asset in assets}
    if not asset_ids:
        return {
            "nodes": [_node("internet", "internet", "Internet", risk="info")],
            "edges": [],
            "meta": {"scan_id": scan_id, "previous_scan_id": None, "delta": delta, "asset_count": 0},
        }

    services = (await db.scalars(
        select(AssetService).where(AssetService.asset_id.in_(asset_ids))
    )).all()

    technologies = (await db.scalars(
        select(AssetTechnology).where(AssetTechnology.asset_id.in_(asset_ids))
    )).all()

    findings = (await db.scalars(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.workspace_id == principal.workspace_id, Scan.asset_id.in_(asset_ids))
        .order_by(Finding.created_at.desc())
    )).all()

    scans = (await db.scalars(
        select(Scan).where(Scan.workspace_id == principal.workspace_id, Scan.asset_id.in_(asset_ids))
        .order_by(Scan.completed_at.desc())
    )).all()

    selected_scan = None
    previous_scan = None
    if scan_id:
        selected_scan = await db.scalar(
            select(Scan).where(Scan.id == scan_id, Scan.workspace_id == principal.workspace_id)
        )
        if not selected_scan:
            raise HTTPException(404, "Scan not found")
        previous_scan = await db.scalar(
            select(Scan).where(
                Scan.asset_id == selected_scan.asset_id,
                Scan.workspace_id == principal.workspace_id,
                Scan.status == "completed",
                Scan.id != selected_scan.id,
            ).order_by(Scan.completed_at.desc())
        )

    current_fingerprints: set[str] = set()
    previous_fingerprints: set[str] = set()
    if selected_scan:
        selected_findings = (await db.scalars(
            select(Finding).where(Finding.scan_id == selected_scan.id)
        )).all()
        current_fingerprints = {f.fingerprint for f in selected_findings}
        if previous_scan:
            previous_rows = (await db.scalars(
                select(Finding).where(Finding.scan_id == previous_scan.id)
            )).all()
            previous_fingerprints = {f.fingerprint for f in previous_rows}

    nodes: list[dict] = [_node(
        "internet", "internet", "Internet",
        subtitle="Authorized external boundary", risk="info", finding_count=0,
    )]
    edges: list[dict] = []
    asset_node_ids: dict[str, str] = {}

    def passes_filter(kind: str, label: str, risk: str = "info") -> bool:
        if node_type and node_type != "all" and kind != node_type:
            return False
        if severity and SEVERITY_RANK.get(risk, 0) < SEVERITY_RANK.get(severity, 0):
            return False
        if q and q.strip().lower() not in label.lower():
            return False
        return True

    findings_by_asset: dict[str, list[Finding]] = {}
    for finding in findings:
        scan = next((s for s in scans if s.id == finding.scan_id), None)
        if scan and scan.asset_id:
            findings_by_asset.setdefault(scan.asset_id, []).append(finding)

    for asset in assets:
        asset_findings = findings_by_asset.get(asset.id, [])
        risk = max((f.severity for f in asset_findings), key=lambda x: SEVERITY_RANK.get(x, 0), default="info")
        node_id = f"asset:{asset.id}"
        asset_node_ids[asset.id] = node_id
        if passes_filter("asset", asset.host, risk):
            nodes.append(_node(
                node_id, "asset", asset.host,
                asset_id=asset.id,
                subtitle=f"{asset.asset_type} · {asset.environment}",
                addresses=list(asset.addresses or []),
                criticality=asset.criticality,
                risk=risk,
                finding_count=len(asset_findings),
                status=asset.status,
                last_seen_at=asset.last_seen_at.isoformat() if asset.last_seen_at else None,
            ))
            edges.append(_edge("internet", node_id, "resolves-to", label="authorized asset"))
        else:
            # Keep relationships usable even when a filter hides a node.
            continue

        for address in asset.addresses or []:
            dns_id = f"dns:{asset.id}:{address}"
            if passes_filter("dns", address):
                nodes.append(_node(dns_id, "dns", address, asset_id=asset.id, subtitle="Observed address", risk=risk))
                edges.append(_edge(node_id, dns_id, "resolves", label="DNS / address"))

    for service in services:
        asset_node = asset_node_ids.get(service.asset_id)
        if not asset_node:
            continue
        label = f"{service.port}/{service.protocol}" + (f" · {service.service}" if service.service else "")
        if not passes_filter("service", label):
            continue
        service_id = f"service:{service.id}"
        service_findings = [f for f in findings_by_asset.get(service.asset_id, []) if _finding_matches_service(f, service)]
        risk = max((f.severity for f in service_findings), key=lambda x: SEVERITY_RANK.get(x, 0), default="info")
        nodes.append(_node(
            service_id, "service", label,
            service_id_ref=service.id, asset_id=service.asset_id,
            port=service.port, protocol=service.protocol, service=service.service,
            state=service.state, risk=risk, finding_count=len(service_findings),
            first_seen_at=service.first_seen_at.isoformat() if service.first_seen_at else None,
            last_seen_at=service.last_seen_at.isoformat() if service.last_seen_at else None,
        ))
        edges.append(_edge(asset_node, service_id, "exposes", label=service.state))
        for finding in service_findings:
            finding_id = f"finding:{finding.id}"
            if passes_filter("finding", finding.title, finding.severity):
                if not any(n["id"] == finding_id for n in nodes):
                    nodes.append(_node(
                        finding_id, "finding", finding.title,
                        finding_id_ref=finding.id, asset_id=service.asset_id,
                        severity=finding.severity, risk=finding.severity,
                        status=finding.status, fingerprint=finding.fingerprint,
                    ))
                edges.append(_edge(service_id, finding_id, "has-finding", label=finding.severity))

    for technology in technologies:
        asset_node = asset_node_ids.get(technology.asset_id)
        if not asset_node:
            continue
        label = technology.product + (f" {technology.version}" if technology.version else "")
        if not passes_filter("technology", label):
            continue
        tech_id = f"technology:{technology.asset_id}:{technology.id}"
        nodes.append(_node(
            tech_id, "technology", label,
            technology_id=technology.id, asset_id=technology.asset_id,
            vendor=technology.vendor, version=technology.version,
            confidence=technology.confidence, risk="info",
        ))
        edges.append(_edge(asset_node, tech_id, "observed-technology", label=technology.source))

    endpoint_seen: set[tuple[str, str]] = set()
    for finding in findings:
        scan = next((s for s in scans if s.id == finding.scan_id), None)
        if not scan or not scan.asset_id or scan.asset_id not in asset_node_ids:
            continue
        endpoint = _finding_endpoint(finding)
        if not endpoint:
            continue
        key = (scan.asset_id, endpoint)
        endpoint_id = f"endpoint:{scan.asset_id}:{abs(hash(endpoint))}"
        if key not in endpoint_seen:
            endpoint_seen.add(key)
            if passes_filter("endpoint", endpoint, finding.severity):
                nodes.append(_node(
                    endpoint_id, "endpoint", endpoint,
                    asset_id=scan.asset_id, risk=finding.severity,
                    finding_count=0,
                ))
                edges.append(_edge(asset_node_ids[scan.asset_id], endpoint_id, "serves", label="observed endpoint"))
        if passes_filter("finding", finding.title, finding.severity):
            finding_id = f"finding:{finding.id}"
            if not any(n["id"] == finding_id for n in nodes):
                nodes.append(_node(
                    finding_id, "finding", finding.title,
                    finding_id_ref=finding.id, asset_id=scan.asset_id,
                    severity=finding.severity, risk=finding.severity,
                    status=finding.status, fingerprint=finding.fingerprint,
                ))
            if key in endpoint_seen:
                edges.append(_edge(endpoint_id, finding_id, "has-finding", label=finding.severity))

    # Reconstruct DNS, endpoint and subdomain relationships from persisted scan observations.
    histories = (await db.scalars(
        select(AssetHistory).where(
            AssetHistory.workspace_id == principal.workspace_id,
            AssetHistory.asset_id.in_(asset_ids),
            AssetHistory.event_type.in_([
                "discovery.subdomains", "discovery.endpoints", "discovery.dns",
            ]),
        ).order_by(AssetHistory.created_at.desc())
    )).all()
    by_host = {a.host: a for a in assets}
    endpoint_history_seen: set[tuple[str, str]] = set()
    for history in histories:
        asset_node = asset_node_ids.get(history.asset_id)
        if not asset_node:
            continue
        metadata = history.metadata_json or {}
        if history.event_type == "discovery.subdomains":
            for raw_host in metadata.get("hosts", []) or []:
                child = by_host.get(str(raw_host).rstrip(".").lower())
                parent = by_host.get(history.asset_id)
                if child and parent and child.id != parent.id and child.id in asset_node_ids and parent.id in asset_node_ids:
                    edges.append(_edge(asset_node_ids[parent.id], asset_node_ids[child.id], "subdomain", label="discovered"))
        elif history.event_type == "discovery.dns":
            for record in metadata.get("records", []) or []:
                if not isinstance(record, dict):
                    continue
                value = str(record.get("value", "")).strip()
                if not value:
                    continue
                dns_id = f"dns-record:{history.asset_id}:{record.get('type', 'unknown')}:{value}"
                if passes_filter("dns", value):
                    if not any(n["id"] == dns_id for n in nodes):
                        nodes.append(_node(
                            dns_id, "dns", value, asset_id=history.asset_id,
                            subtitle=str(record.get("type", "DNS")), risk="info",
                        ))
                    edges.append(_edge(asset_node, dns_id, "dns-record", label=str(record.get("type", "DNS"))))
        elif history.event_type == "discovery.endpoints":
            for raw_endpoint in metadata.get("endpoints", []) or []:
                endpoint = str(raw_endpoint).strip()
                key = (history.asset_id, endpoint)
                if not endpoint or key in endpoint_history_seen:
                    continue
                endpoint_history_seen.add(key)
                endpoint_id = f"endpoint-history:{history.asset_id}:{abs(hash(endpoint))}"
                if passes_filter("endpoint", endpoint):
                    if not any(n["id"] == endpoint_id for n in nodes):
                        nodes.append(_node(
                            endpoint_id, "endpoint", endpoint, asset_id=history.asset_id,
                            risk="info", finding_count=0,
                        ))
                    edges.append(_edge(asset_node, endpoint_id, "serves", label="scanner inventory"))

    # Attach every observed finding to its asset, regardless of whether it has a port or endpoint.
    for finding in findings:
        scan = next((s for s in scans if s.id == finding.scan_id), None)
        if not scan or scan.asset_id not in asset_node_ids:
            continue
        if not passes_filter("finding", finding.title, finding.severity):
            continue
        finding_id = f"finding:{finding.id}"
        if not any(n["id"] == finding_id for n in nodes):
            nodes.append(_node(
                finding_id, "finding", finding.title,
                finding_id_ref=finding.id, asset_id=scan.asset_id,
                severity=finding.severity, risk=finding.severity,
                status=finding.status, fingerprint=finding.fingerprint,
            ))
        edges.append(_edge(asset_node_ids[scan.asset_id], finding_id, "has-finding", label=finding.severity))

    # Delta annotations are derived from the selected scan's immutable finding fingerprints.
    if selected_scan:
        for node in nodes:
            if node["type"] != "finding":
                continue
            fp = node.get("fingerprint")
            if fp in current_fingerprints and fp not in previous_fingerprints:
                node["delta"] = "new"
            elif fp in previous_fingerprints and fp in current_fingerprints:
                node["delta"] = "persistent"
        for edge in edges:
            if edge["relation"] == "has-finding":
                target = next((n for n in nodes if n["id"] == edge["target"]), None)
                if target and target.get("delta") == "new":
                    edge["delta"] = "new"

    # Deduplicate graph edges while preserving first observed relation.
    unique_edges = list({edge["id"]: edge for edge in edges}.values())

    return {
        "nodes": nodes,
        "edges": unique_edges,
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_id": selected_scan.id if selected_scan else None,
            "previous_scan_id": previous_scan.id if previous_scan else None,
            "delta": delta,
            "asset_count": len(assets),
            "service_count": len(services),
            "finding_count": len(findings),
            "node_count": len(nodes),
            "edge_count": len(unique_edges),
            "available_scans": [
                {
                    "id": s.id,
                    "asset_id": s.asset_id,
                    "host": s.host,
                    "profile": s.profile,
                    "status": s.status,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                    "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                }
                for s in scans[:100]
            ],
        },
    }
