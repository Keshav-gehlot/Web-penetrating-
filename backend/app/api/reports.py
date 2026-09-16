from __future__ import annotations

from io import BytesIO

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Finding, Scan
from sqlalchemy import select

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


@router.get("/{scan_id}.pdf")
async def report_pdf(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    rows = await db.scalars(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at.asc())
    )
    findings = rows.all()

    buffer = BytesIO()
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    story = [
        Paragraph("PHANTOM Security Assessment", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Target: {scan.target}", styles["Normal"]),
        Paragraph(f"Profile: {scan.profile}", styles["Normal"]),
        Paragraph(f"Status: {scan.status}", styles["Normal"]),
        Spacer(1, 18),
    ]

    table_rows = [["Severity", "Module", "Finding", "Confidence"]]
    table_rows += [
        [
            str(f.severity),
            str(f.module),
            str(f.title)[:90],
            f"{float(f.confidence) * 100:.0f}%",
        ]
        for f in findings
    ]
    if len(table_rows) == 1:
        table_rows.append(["—", "—", "No findings recorded", "—"])

    table = Table(table_rows, colWidths=[60, 90, 300, 60], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#20242a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story += [
        table,
        Spacer(1, 18),
        Paragraph(
            "Evidence and remediation are retained in the PHANTOM scan result for analyst review.",
            styles["Normal"],
        ),
    ]

    doc.build(story)
    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="phantom-{scan_id}.pdf"'},
    )
