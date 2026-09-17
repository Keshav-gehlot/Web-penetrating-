from __future__ import annotations
from io import BytesIO
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, PageBreak, KeepTogether
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import Principal
from ..database import get_db
from ..models import Finding, Scan
from ..rbac import require_permission

router=APIRouter(prefix="/api/v1/reports",tags=["reports"])
SEVERITIES=("critical","high","medium","low","info")

@router.get("/{scan_id}.pdf")
async def report_pdf(scan_id:str,principal:Principal=Depends(require_permission("report:export")),db:AsyncSession=Depends(get_db)):
    scan=await db.scalar(select(Scan).where(Scan.id==scan_id,Scan.workspace_id==principal.workspace_id))
    if not scan:raise HTTPException(404,"Scan not found")
    rows=await db.scalars(select(Finding).where(Finding.scan_id==scan_id).order_by(Finding.severity.desc(),Finding.created_at.asc()));findings=rows.all()
    counts={s:sum(1 for f in findings if f.severity==s) for s in SEVERITIES}
    open_count=sum(1 for f in findings if f.status not in {"closed","false_positive"})
    buffer=BytesIO();styles=getSampleStyleSheet();body=ParagraphStyle("body",parent=styles["BodyText"],fontSize=9,leading=13,spaceAfter=5);small=ParagraphStyle("small",parent=body,fontSize=7,leading=10);heading=ParagraphStyle("heading",parent=styles["Heading2"],fontSize=15,leading=18,spaceBefore=8,spaceAfter=8);center=ParagraphStyle("center",parent=body,alignment=TA_CENTER)
    doc=SimpleDocTemplate(buffer,pagesize=A4,rightMargin=16*mm,leftMargin=16*mm,topMargin=16*mm,bottomMargin=16*mm,title="PHANTOM Security Assessment",author="PHANTOM")
    story=[Paragraph("PHANTOM Security Assessment",styles["Title"]),Paragraph("Authorized security assessment report",center),Spacer(1,10),Paragraph(f"<b>Target:</b> {scan.target}",body),Paragraph(f"<b>Host:</b> {scan.host}",body),Paragraph(f"<b>Profile:</b> {scan.profile} &nbsp;&nbsp; <b>Status:</b> {scan.status}",body),Paragraph(f"<b>Scan ID:</b> {scan.id}",small),Paragraph(f"<b>Created:</b> {scan.created_at.isoformat() if scan.created_at else '—'}",small),Paragraph(f"<b>Completed:</b> {scan.completed_at.isoformat() if scan.completed_at else '—'}",small),Spacer(1,12),Paragraph("Executive Summary",heading),Paragraph(f"PHANTOM recorded {len(findings)} finding(s) during this assessment, of which {open_count} remain outside the closed/false-positive states. Results are assessment signals and should be validated by an authorized analyst before remediation decisions.",body),Paragraph("Scope",heading),Paragraph("The report contains only the persisted scan represented by this scan ID and the workspace to which the authenticated operator belongs. No unrecorded test activity is inferred.",body),Paragraph("Methodology",heading),Paragraph("The selected PHANTOM profile runs bounded, non-destructive assessment modules with request, redirect, response-size, concurrency and execution-time controls. Candidate findings are not presented as proof of exploitability.",body),Paragraph("Risk Overview",heading)]
    overview=[[Paragraph("Severity",small),Paragraph("Count",small)]]+[[Paragraph(s.upper(),small),Paragraph(str(counts[s]),small)] for s in SEVERITIES]
    table=Table(overview,colWidths=[55*mm,25*mm],repeatRows=1);table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#20242a")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.25,colors.grey),("ALIGN",(1,1),(1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE")]))
    story += [table,PageBreak(),Paragraph("Findings",styles["Title"])]
    if not findings: story.append(Paragraph("No findings were recorded for this scan.",body))
    for index,f in enumerate(findings,1):
        evidence=f.evidence or {}; evidence_text=str(evidence)[:3500].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        block=[Paragraph(f"{index}. {f.title}",heading),Paragraph(f"<b>Severity:</b> {f.severity.upper()} &nbsp;&nbsp; <b>Status:</b> {f.status} &nbsp;&nbsp; <b>Confidence:</b> {float(f.confidence)*100:.0f}%",body),Paragraph(f"<b>Module:</b> {f.module} &nbsp;&nbsp; <b>CVE:</b> {f.cve or '—'} &nbsp;&nbsp; <b>CWE:</b> {f.cwe or '—'} &nbsp;&nbsp; <b>CVSS:</b> {f.cvss if f.cvss is not None else '—'}",body),Paragraph("Description",styles["Heading3"]),Paragraph((f.description or "No description recorded.").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"),body),Paragraph("Evidence",styles["Heading3"]),Paragraph(evidence_text or "{}",small),Paragraph(f"<b>Evidence SHA-256:</b> {f.evidence_hash or '—'} &nbsp;&nbsp; <b>Source:</b> {f.evidence_source}",small),Paragraph("Remediation",styles["Heading3"]),Paragraph((f.remediation or "No remediation guidance recorded.").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"),body)]
        story.append(KeepTogether(block));story.append(Spacer(1,5))
    story += [Spacer(1,10),Paragraph("Technical Appendix",heading),Paragraph(f"Profile: {scan.profile}<br/>Modules: {', '.join(scan.modules)}<br/>Attempt: {scan.attempt}<br/>Worker: {scan.worker_id or 'completed'}",small),Spacer(1,8),Paragraph("Report generated from persisted PHANTOM data. Evidence is retained with a SHA-256 provenance digest for analyst verification.",small)]
    doc.build(story);buffer.seek(0)
    return StreamingResponse(buffer,media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="phantom-{scan_id}.pdf"'})
