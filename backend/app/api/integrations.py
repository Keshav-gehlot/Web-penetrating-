from __future__ import annotations
from datetime import datetime,timezone
import json,smtplib,ssl,urllib.error,urllib.request
from email.message import EmailMessage
from fastapi import APIRouter,Depends,HTTPException,Request
from pydantic import BaseModel,Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..api.audit import record_audit
from ..auth import Principal
from ..database import get_db
from ..models import Finding,Integration,IntegrationDelivery,Scan
from ..rbac import require_permission

router=APIRouter(prefix="/api/v1/integrations",tags=["integrations"])
PROVIDERS={"jira","github","slack","pagerduty","email"}

class IntegrationInput(BaseModel):
 provider:str
 name:str=Field(min_length=1,max_length=120)
 enabled:bool=True
 config:dict=Field(default_factory=dict)
 secret:str|None=None

def public(i):
 return {"id":i.id,"provider":i.provider,"name":i.name,"enabled":i.enabled,"status":i.status,
 "config":i.config or {},"has_secret":bool(i.secret),"last_verified_at":i.last_verified_at.isoformat() if i.last_verified_at else None,
 "last_error":i.last_error,"created_at":i.created_at.isoformat() if i.created_at else None}

def request_json(url,method="GET",headers=None,data=None,timeout=8):
 req=urllib.request.Request(url,data=json.dumps(data).encode() if data is not None else None,headers=headers or {},method=method)
 try:
  with urllib.request.urlopen(req,timeout=timeout) as res:
   body=res.read().decode()
   return res.status,json.loads(body) if body else {}
 except urllib.error.HTTPError as e:
  raise RuntimeError(f"provider returned HTTP {e.code}")

def verify(i):
 p=i.provider;cfg=i.config or {};secret=i.secret or ""
 if p=="slack":
  if not secret.startswith("https://hooks.slack.com/"):raise RuntimeError("Slack webhook URL required")
  return
 if p=="github":
  if not secret:raise RuntimeError("GitHub token required")
  status,_=request_json("https://api.github.com/user",headers={"Authorization":f"Bearer {secret}","Accept":"application/vnd.github+json","User-Agent":"PHANTOM"})
  if status!=200:raise RuntimeError("GitHub credential verification failed")
  if not cfg.get("repo"):raise RuntimeError("GitHub repo (owner/name) required")
  return
 if p=="jira":
  base=str(cfg.get("base_url","")).rstrip("/");email=cfg.get("email")
  if not base.startswith("https://") or not email or not secret:raise RuntimeError("Jira base_url, email and API token required")
  import base64
  auth=base64.b64encode(f"{email}:{secret}".encode()).decode()
  status,_=request_json(base+"/rest/api/3/myself",headers={"Authorization":f"Basic {auth}","Accept":"application/json"})
  if status!=200:raise RuntimeError("Jira credential verification failed")
  if not cfg.get("project_key"):raise RuntimeError("Jira project_key required")
  return
 if p=="pagerduty":
  if not secret:raise RuntimeError("PagerDuty routing key required")
  return
 if p=="email":
  for k in ("smtp_host","from_email","to_email"):
   if not cfg.get(k):raise RuntimeError(f"Email {k} required")
  return
 raise RuntimeError("Unsupported provider")

def finding_payload(f):
 return {"title":f.title,"severity":f.severity,"status":f.status,"description":f.description,"remediation":f.remediation,"finding_id":f.id,"scan_id":f.scan_id}

def deliver(i,f):
 p=i.provider;cfg=i.config or {};secret=i.secret or "";x=finding_payload(f)
 title=f"[PHANTOM {x['severity'].upper()}] {x['title']}"
 body=f"{x['description']}\n\nRemediation: {x['remediation']}\nFinding: {x['finding_id']}"
 if p=="slack":
  status,data=request_json(secret,"POST",{"Content-Type":"application/json"},{"text":title+"\n"+body});return str(data.get("ts","")),None
 if p=="github":
  repo=cfg["repo"];status,data=request_json(f"https://api.github.com/repos/{repo}/issues","POST",{"Authorization":f"Bearer {secret}","Accept":"application/vnd.github+json","Content-Type":"application/json","User-Agent":"PHANTOM"},{"title":title,"body":body,"labels":cfg.get("labels",[])})
  return str(data.get("number","")),data.get("html_url")
 if p=="jira":
  import base64
  base=str(cfg["base_url"]).rstrip("/");auth=base64.b64encode(f"{cfg['email']}:{secret}".encode()).decode()
  status,data=request_json(base+"/rest/api/3/issue","POST",{"Authorization":f"Basic {auth}","Accept":"application/json","Content-Type":"application/json"},{"fields":{"project":{"key":cfg["project_key"]},"summary":title,"description":{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":body[:30000]}]}]},"issuetype":{"name":cfg.get("issue_type","Bug")}}})
  key=data.get("key");return key,(base+"/browse/"+key) if key else None
 if p=="pagerduty":
  status,data=request_json("https://events.pagerduty.com/v2/enqueue","POST",{"Content-Type":"application/json"},{"routing_key":secret,"event_action":"trigger","dedup_key":"phantom-"+f.id,"payload":{"summary":title,"source":"PHANTOM","severity":"critical" if f.severity=="critical" else "warning","custom_details":x}})
  return data.get("dedup_key"),None
 if p=="email":
  msg=EmailMessage();msg["Subject"]=title;msg["From"]=cfg["from_email"];msg["To"]=cfg["to_email"];msg.set_content(body)
  port=int(cfg.get("smtp_port",587));host=cfg["smtp_host"]
  with smtplib.SMTP(host,port,timeout=10) as s:
   if cfg.get("starttls",True):s.starttls(context=ssl.create_default_context())
   if cfg.get("username") and secret:s.login(cfg["username"],secret)
   s.send_message(msg)
  return None,None
 raise RuntimeError("Unsupported provider")

@router.get("")
async def list_integrations(principal:Principal=Depends(require_permission("workspace:manage")),db:AsyncSession=Depends(get_db)):
 rows=await db.scalars(select(Integration).where(Integration.workspace_id==principal.workspace_id).order_by(Integration.provider));return [public(x) for x in rows.all()]

@router.put("/{provider}")
async def configure(provider:str,payload:IntegrationInput,request:Request,principal:Principal=Depends(require_permission("workspace:manage")),db:AsyncSession=Depends(get_db)):
 provider=provider.lower()
 if provider not in PROVIDERS or payload.provider.lower()!=provider:raise HTTPException(400,"Invalid provider")
 i=await db.scalar(select(Integration).where(Integration.workspace_id==principal.workspace_id,Integration.provider==provider))
 if not i:i=Integration(workspace_id=principal.workspace_id,provider=provider,name=payload.name,created_by=principal.user_id);db.add(i)
 i.name=payload.name;i.enabled=payload.enabled;i.config=payload.config
 if payload.secret is not None:i.secret=payload.secret
 i.status="unverified";i.last_error=None
 await record_audit(db,request,"integration.configured","integration",provider,{"enabled":i.enabled},principal);await db.commit();await db.refresh(i);return public(i)

@router.post("/{provider}/verify")
async def verify_integration(provider:str,request:Request,principal:Principal=Depends(require_permission("workspace:manage")),db:AsyncSession=Depends(get_db)):
 i=await db.scalar(select(Integration).where(Integration.workspace_id==principal.workspace_id,Integration.provider==provider.lower()))
 if not i:raise HTTPException(404,"Integration not configured")
 try:verify(i);i.status="connected";i.last_verified_at=datetime.now(timezone.utc);i.last_error=None
 except Exception as e:i.status="error";i.last_error=str(e)[:500]
 await record_audit(db,request,"integration.verified","integration",i.id,{"status":i.status,"error":i.last_error},principal);await db.commit();await db.refresh(i)
 if i.status!="connected":raise HTTPException(422,i.last_error)
 return public(i)

@router.delete("/{provider}")
async def disconnect(provider:str,request:Request,principal:Principal=Depends(require_permission("workspace:manage")),db:AsyncSession=Depends(get_db)):
 i=await db.scalar(select(Integration).where(Integration.workspace_id==principal.workspace_id,Integration.provider==provider.lower()))
 if not i:raise HTTPException(404,"Integration not configured")
 await record_audit(db,request,"integration.disconnected","integration",i.id,{"provider":i.provider},principal);await db.delete(i);await db.commit();return {"ok":True}

@router.post("/{provider}/findings/{finding_id}")
async def send_finding(provider:str,finding_id:str,request:Request,principal:Principal=Depends(require_permission("finding:edit")),db:AsyncSession=Depends(get_db)):
 i=await db.scalar(select(Integration).where(Integration.workspace_id==principal.workspace_id,Integration.provider==provider.lower()))
 if not i or not i.enabled or i.status!="connected":raise HTTPException(409,"Integration is not verified and connected")
 f=await db.scalar(select(Finding).join(Scan).where(Finding.id==finding_id,Scan.workspace_id==principal.workspace_id))
 if not f:raise HTTPException(404,"Finding not found")
 d=IntegrationDelivery(workspace_id=principal.workspace_id,integration_id=i.id,finding_id=f.id,event_type="finding.exported",status="pending");db.add(d)
 try:d.external_id,d.external_url=deliver(i,f);d.status="delivered"
 except Exception as e:d.status="failed";d.error=str(e)[:1000]
 await record_audit(db,request,"integration.delivery","finding",f.id,{"provider":i.provider,"status":d.status,"external_id":d.external_id},principal);await db.commit();await db.refresh(d)
 if d.status=="failed":raise HTTPException(502,d.error)
 return {"id":d.id,"status":d.status,"external_id":d.external_id,"external_url":d.external_url}
