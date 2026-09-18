from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Principal
from ..database import get_db
from ..models import CVEIntelligence
from ..rbac import require_permission

router = APIRouter(prefix="/api/v1/intelligence", tags=["intelligence"])


def serialize(row: CVEIntelligence) -> dict:
    return {
        "cve": row.cve, "product": row.product, "version": row.version, "cpe": row.cpe,
        "description": row.description, "severity": row.severity, "cvss": row.cvss,
        "cvss_v3": {"score": row.cvss_v3_score, "vector": row.cvss_v3_vector, "severity": row.cvss_v3_severity} if row.cvss_v3_score is not None else None,
        "cvss_v4": {"score": row.cvss_v4_score, "vector": row.cvss_v4_vector, "severity": row.cvss_v4_severity} if row.cvss_v4_score is not None else None,
        "published_at": row.published_at.isoformat() if row.published_at else None,
        "modified_at": row.modified_at.isoformat() if row.modified_at else None,
        "affected_versions": row.affected_versions or [], "references": row.references or [],
        "remediation": row.remediation, "source": row.source,
        "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None,
    }


@router.get("/cves/{cve}")
async def get_cve(cve: str, principal: Principal = Depends(require_permission("finding:view")), db: AsyncSession = Depends(get_db)):
    del principal
    row = await db.scalar(select(CVEIntelligence).where(CVEIntelligence.cve == cve.upper()))
    if not row:
        raise HTTPException(404, "CVE intelligence not available")
    return serialize(row)
