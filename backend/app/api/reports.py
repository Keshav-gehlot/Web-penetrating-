from io import BytesIO
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from .scans import SCANS

router=APIRouter(prefix="/api/v1/reports",tags=["reports"])

@router.get("/{scan_id}.pdf")
async def report_pdf(scan_id:str):
    scan=SCANS.get(scan_id)
    if not scan: raise HTTPException(404,"Scan not found")
    buf=BytesIO(); styles=getSampleStyleSheet(); doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36)
    story=[Paragraph("PHANTOM Security Assessment",styles["Title"]),Spacer(1,12),Paragraph(f"Target: {scan['target']}",styles["Normal"]),Paragraph(f"Profile: {scan['profile']}",styles["Normal"]),Paragraph(f"Status: {scan['status']}",styles["Normal"]),Spacer(1,18)]
    findings=scan.get("findings",[])
    rows=[["Severity","Module","Finding","Confidence"]]
    rows += [[str(f.get("severity","info")),str(f.get("module","")),str(f.get("title",""))[:90],f"{float(f.get('confidence',0))*100:.0f}%"] for f in findings]
    table=Table(rows,colWidths=[60,90,300,60],repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#20242a")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.25,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),8)]))
    story += [table,Spacer(1,18),Paragraph("Evidence and remediation are retained in the scan result API for analyst review.",styles["Normal"])]
    doc.build(story); buf.seek(0)
    return StreamingResponse(buf,media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="phantom-{scan_id}.pdf"'})
