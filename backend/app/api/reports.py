from __future__ import annotations
from datetime import datetime, timezone
from html import escape
from io import BytesIO
from uuid import uuid4
from fastapi import APIRouter,Depends,HTTPException,Request
from fastapi.responses import HTMLResponse,StreamingResponse
from pydantic import BaseModel,Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,PageBreak
from ..auth import Principal
from ..database import get_db
from ..models import Finding,Scan,Report,ReportVersion,ReportDownload
from ..rbac import require_permission
from .audit import record_audit

router=APIRouter(prefix="/api/v1/reports",tags=["reports"])
TEMPLATES={
 "executive":{"name":"Executive report","sections":["Executive Summary","Risk Overview","Priority Actions"]},
 "technical":{"name":"Technical report","sections":["Executive Summary","Scope","Methodology","Risk Overview","Findings","Technical Appendix"]},
}
class ReportCreate(BaseModel):
 scan_id:str; title:str=Field(min_length=1,max_length=240); template:str="technical"; metadata:dict=Field(default_factory=dict); branding:dict=Field(default_factory=dict); sections:list[dict]=Field(default_factory=list); finding_ids:list[str]=Field(default_factory=list); include_evidence:bool=True
class ReportUpdate(BaseModel):
 title:str|None=None; template:str|None=None; status:str|None=None; metadata:dict|None=None; branding:dict|None=None; sections:list[dict]|None=None; finding_ids:list[str]|None=None; include_evidence:bool|None=None

def snapshot(r:Report)->dict:
 return {"title":r.title,"template":r.template,"status":r.status,"metadata":r.metadata_json or {},"branding":r.branding or {},"sections":r.sections or [],"finding_ids":r.finding_ids or [],"include_evidence":r.include_evidence}
def out(r:Report)->dict:
 return {"id":r.id,"scan_id":r.scan_id,"title":r.title,"template":r.template,"status":r.status,"metadata":r.metadata_json or {},"branding":r.branding or {},"sections":r.sections or [],"finding_ids":r.finding_ids or [],"include_evidence":r.include_evidence,"current_version":r.current_version,"created_at":r.created_at,"updated_at":r.updated_at}
async def get_report(db,id,ws):
 r=await db.scalar(select(Report).where(Report.id==id,Report.workspace_id==ws))
 if not r: raise HTTPException(404,"Report not found")
 return r
async def report_data(db,r):
 scan=await db.scalar(select(Scan).where(Scan.id==r.scan_id,Scan.workspace_id==r.workspace_id))
 if not scan: raise HTTPException(404,"Source scan not found")
 fs=(await db.scalars(select(Finding).where(Finding.scan_id==scan.id).order_by(Finding.created_at.asc()))).all()
 if r.finding_ids: fs=[f for f in fs if f.id in set(r.finding_ids)]
 return scan,fs
def sections(r):
 return r.sections or [{"title":x,"content":""} for x in TEMPLATES.get(r.template,TEMPLATES["technical"])["sections"]]
def html_doc(r,scan,fs):
 counts={s:sum(1 for f in fs if f.severity==s) for s in ["critical","high","medium","low","info"]}
 brand=r.branding or {}; company=escape(str(brand.get("company","PHANTOM"))); accent=escape(str(brand.get("accent","#111827")))
 custom="".join(f"<section><h2>{escape(str(s.get('title','Section')))}</h2><p>{escape(str(s.get('content','')))}</p></section>" for s in sections(r) if s.get("content"))
 findings="".join(f"<article><h3>{escape(f.title)} <small>{escape(f.severity.upper())}</small></h3><p>{escape(f.description or '')}</p>{('<pre>'+escape(str(f.evidence or {}))+'</pre>') if r.include_evidence else ''}<h4>Remediation</h4><p>{escape(f.remediation or '')}</p></article>" for f in fs)
 return f"""<!doctype html><html><head><meta charset="utf-8"><title>{escape(r.title)}</title><style>body{{font:14px system-ui;margin:40px;color:#111}}header{{border-bottom:3px solid {accent};padding-bottom:18px}}h1,h2{{color:{accent}}}.grid{{display:flex;gap:12px}}.grid b{{padding:12px;border:1px solid #ddd}}article{{border-top:1px solid #ddd;padding:14px 0}}pre{{white-space:pre-wrap;background:#f5f5f5;padding:10px}}</style></head><body><header><b>{company}</b><h1>{escape(r.title)}</h1><p>{escape(scan.target)} · {escape(r.template)} · v{r.current_version} · {escape(r.status)}</p></header><h2>Risk Overview</h2><div class="grid">{''.join(f'<b>{s}: {counts[s]}</b>' for s in counts)}</div>{custom}<h2>Findings</h2>{findings or '<p>No selected findings.</p>'}</body></html>"""
async def log_download(db,r,p,fmt):
 db.add(ReportDownload(id=str(uuid4()),report_id=r.id,version=r.current_version,format=fmt,downloaded_by=p.user_id));await db.commit()

@router.get("/templates")
async def templates(p:Principal=Depends(require_permission("report:create"))): return TEMPLATES
@router.get("")
async def list_reports(p:Principal=Depends(require_permission("scan:view")),db:AsyncSession=Depends(get_db)):
 return [out(x) for x in (await db.scalars(select(Report).where(Report.workspace_id==p.workspace_id).order_by(Report.updated_at.desc()))).all()]
@router.post("")
async def create_report(body:ReportCreate,request:Request,p:Principal=Depends(require_permission("report:create")),db:AsyncSession=Depends(get_db)):
 if body.template not in TEMPLATES: raise HTTPException(400,"Unknown report template")
 scan=await db.scalar(select(Scan).where(Scan.id==body.scan_id,Scan.workspace_id==p.workspace_id))
 if not scan: raise HTTPException(404,"Scan not found")
 r=Report(id=str(uuid4()),workspace_id=p.workspace_id,scan_id=body.scan_id,created_by=p.user_id,title=body.title,template=body.template,metadata_json=body.metadata,branding=body.branding,sections=body.sections,finding_ids=body.finding_ids,include_evidence=body.include_evidence,current_version=1,status="draft")
 db.add(r);await db.flush();db.add(ReportVersion(id=str(uuid4()),report_id=r.id,version=1,snapshot=snapshot(r),created_by=p.user_id));await record_audit(db,request,"report.created","report",r.id,{"scan_id":r.scan_id,"template":r.template},p);await db.commit();await db.refresh(r);return out(r)
@router.get("/{report_id}")
async def detail(report_id:str,p:Principal=Depends(require_permission("scan:view")),db:AsyncSession=Depends(get_db)): return out(await get_report(db,report_id,p.workspace_id))
@router.patch("/{report_id}")
async def update(report_id:str,body:ReportUpdate,request:Request,p:Principal=Depends(require_permission("report:create")),db:AsyncSession=Depends(get_db)):
 r=await get_report(db,report_id,p.workspace_id);data=body.model_dump(exclude_unset=True)
 if data.get("template") and data["template"] not in TEMPLATES: raise HTTPException(400,"Unknown report template")
 if data.get("status") and data["status"] not in {"draft","review","final","archived"}: raise HTTPException(400,"Invalid report status")
 mapping={"metadata":"metadata_json"}
 for k,v in data.items(): setattr(r,mapping.get(k,k),v)
 r.current_version+=1;await db.flush();db.add(ReportVersion(id=str(uuid4()),report_id=r.id,version=r.current_version,snapshot=snapshot(r),created_by=p.user_id));await record_audit(db,request,"report.version_created","report",r.id,{"version":r.current_version,"status":r.status},p);await db.commit();await db.refresh(r);return out(r)
@router.get("/{report_id}/versions")
async def versions(report_id:str,p:Principal=Depends(require_permission("scan:view")),db:AsyncSession=Depends(get_db)):
 r=await get_report(db,report_id,p.workspace_id);return [{"version":v.version,"snapshot":v.snapshot,"created_at":v.created_at} for v in (await db.scalars(select(ReportVersion).where(ReportVersion.report_id==r.id).order_by(ReportVersion.version.desc()))).all()]
@router.get("/{report_id}/downloads")
async def downloads(report_id:str,p:Principal=Depends(require_permission("scan:view")),db:AsyncSession=Depends(get_db)):
 r=await get_report(db,report_id,p.workspace_id);return [{"version":x.version,"format":x.format,"downloaded_by":x.downloaded_by,"downloaded_at":x.downloaded_at} for x in (await db.scalars(select(ReportDownload).where(ReportDownload.report_id==r.id).order_by(ReportDownload.downloaded_at.desc()))).all()]
@router.get("/{report_id}/export.html")
async def export_html(report_id:str,request:Request,p:Principal=Depends(require_permission("report:export")),db:AsyncSession=Depends(get_db)):
 r=await get_report(db,report_id,p.workspace_id);scan,fs=await report_data(db,r);body=html_doc(r,scan,fs);await log_download(db,r,p,"html");await record_audit(db,request,"report.exported","report",r.id,{"format":"html","version":r.current_version},p);await db.commit();return HTMLResponse(body,headers={"Content-Disposition":f'attachment; filename="report-{r.id}-v{r.current_version}.html"'})
@router.get("/{report_id}/export.pdf")
async def export_pdf(report_id:str,request:Request,p:Principal=Depends(require_permission("report:export")),db:AsyncSession=Depends(get_db)):
 r=await get_report(db,report_id,p.workspace_id);scan,fs=await report_data(db,r);buf=BytesIO();styles=getSampleStyleSheet();doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=16*mm,leftMargin=16*mm,topMargin=16*mm,bottomMargin=16*mm,title=r.title);story=[Paragraph(escape(r.title),styles["Title"]),Paragraph(f"{escape(scan.target)} · {escape(r.template)} · version {r.current_version}",styles["BodyText"]),Spacer(1,12)]
 for s in sections(r):
  if s.get("content"): story += [Paragraph(escape(str(s.get("title","Section"))),styles["Heading2"]),Paragraph(escape(str(s.get("content",""))),styles["BodyText"]),Spacer(1,8)]
 story += [Paragraph("Findings",styles["Heading1"])]
 for f in fs:
  story += [Paragraph(escape(f.title),styles["Heading2"]),Paragraph(f"Severity: {escape(f.severity.upper())} · Status: {escape(f.status)}",styles["BodyText"]),Paragraph(escape(f.description or ""),styles["BodyText"])]
  if r.include_evidence: story += [Paragraph("Evidence",styles["Heading3"]),Paragraph(escape(str(f.evidence or {}))[:5000],ParagraphStyle("e",parent=styles["BodyText"],fontSize=7))]
  story += [Paragraph("Remediation",styles["Heading3"]),Paragraph(escape(f.remediation or ""),styles["BodyText"]),Spacer(1,10)]
 doc.build(story);buf.seek(0);await log_download(db,r,p,"pdf");await record_audit(db,request,"report.exported","report",r.id,{"format":"pdf","version":r.current_version},p);await db.commit();return StreamingResponse(buf,media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="report-{r.id}-v{r.current_version}.pdf"'})

# Backward-compatible scan PDF export.
@router.get("/scan/{scan_id}.pdf")
async def legacy_pdf(scan_id:str,p:Principal=Depends(require_permission("report:export")),db:AsyncSession=Depends(get_db)):
 scan=await db.scalar(select(Scan).where(Scan.id==scan_id,Scan.workspace_id==p.workspace_id))
 if not scan: raise HTTPException(404,"Scan not found")
 fs=(await db.scalars(select(Finding).where(Finding.scan_id==scan_id))).all();buf=BytesIO();doc=SimpleDocTemplate(buf,pagesize=A4);styles=getSampleStyleSheet();story=[Paragraph("PHANTOM Security Assessment",styles["Title"]),Paragraph(escape(scan.target),styles["BodyText"])]
 for f in fs: story += [Paragraph(escape(f.title),styles["Heading2"]),Paragraph(escape(f.description or ""),styles["BodyText"])]
 doc.build(story);buf.seek(0);return StreamingResponse(buf,media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="phantom-{scan_id}.pdf"'})
