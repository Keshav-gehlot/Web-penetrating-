from __future__ import annotations
import asyncio, logging, socket
from datetime import datetime, timedelta, timezone
from typing import Any
import psutil
from sqlalchemy import delete, select
from .config import settings
from .database import SessionLocal
from .models import Finding, NetWatchBaseline, NetWatchEvent, Scan, Workspace
from .network_anomaly import engine
from .network_monitor import monitor

log = logging.getLogger("phantom.net_watch")
_previous_connections: dict[str, dict[str, Any]] = {}
_previous_processes: dict[int, dict[str, Any]] = {}
_previous_interfaces: dict[str, dict[str, Any]] = {}
_sample_no = 0

def _processes():
    out={}
    for p in psutil.process_iter(["pid","ppid","name","username","create_time"]):
        try: out[p.info["pid"]]=p.info
        except (psutil.NoSuchProcess,psutil.AccessDenied): continue
    return out

async def _baseline(db,workspace_id,metric,value):
    row=await db.scalar(select(NetWatchBaseline).where(NetWatchBaseline.workspace_id==workspace_id,NetWatchBaseline.metric==metric))
    if not row:
        row=NetWatchBaseline(workspace_id=workspace_id,metric=metric,value={"mean":float(value),"last":float(value)},sample_count=1);db.add(row);return row
    old=float((row.value or {}).get("mean",value));n=row.sample_count or 0;alpha=min(.2,2/(min(n,30)+1))
    row.value={"mean":(1-alpha)*old+alpha*float(value),"last":float(value)};row.sample_count=n+1;return row

async def _correlate(db,workspace_id,event):
    data=event.data or {};remote=data.get("remote") or "";port=None;ip=None
    if isinstance(remote,str) and ":" in remote:
        ip,_,raw=remote.rpartition(":")
        try:port=int(raw)
        except ValueError:port=None
    rows=(await db.scalars(select(Finding).join(Scan).where(Scan.workspace_id==workspace_id).order_by(Finding.last_seen.desc()).limit(500))).all()
    for f in rows:
        evidence=f.evidence or {}
        if (port and str(evidence.get("port",""))==str(port)) or (ip and ip in str(evidence)):
            event.finding_id=f.id;return

async def collect_once():
    global _previous_connections,_previous_processes,_previous_interfaces,_sample_no
    _sample_no+=1
    snapshot=await asyncio.to_thread(monitor.snapshot,True)
    anomaly=engine.observe(snapshot)
    processes=await asyncio.to_thread(_processes)
    interfaces=(snapshot.get("network_io") or {}).get("interfaces") or {}
    current_connections={c["key"]:c for c in snapshot.get("connections",[])}
    opened=[v for k,v in current_connections.items() if k not in _previous_connections] if _previous_connections else []
    closed=[v for k,v in _previous_connections.items() if k not in current_connections] if _previous_connections else []
    process_events=[]
    if _previous_processes:
        for pid in processes.keys()-_previous_processes.keys():process_events.append({**processes[pid],"action":"started"})
        for pid in _previous_processes.keys()-processes.keys():process_events.append({**_previous_processes[pid],"action":"stopped"})
    interface_events=[]
    if _previous_interfaces:
        for name,data in interfaces.items():
            old=_previous_interfaces.get(name)
            if old is None or old.get("is_up")!=data.get("is_up") or _sample_no%10==0:
                interface_events.append({"name":name,**data,"previous_is_up":old.get("is_up") if old else None,"periodic":bool(old and old.get("is_up")==data.get("is_up"))})
    async with SessionLocal() as db:
        workspaces=(await db.scalars(select(Workspace))).all()
        for ws in workspaces:
            events=[]
            for d in opened:
                events.append(NetWatchEvent(workspace_id=ws.id,kind="connection",severity=d.get("risk","info"),summary="Connection opened",explanation="A network connection appeared in native OS telemetry. "+("; ".join(d.get("risk_reasons") or []) or "No elevated rule-based risk signal was identified."),data={**d,"action":"opened","sensor":snapshot.get("hostname")},baseline={}))
            for d in closed:
                events.append(NetWatchEvent(workspace_id=ws.id,kind="connection",severity="info",summary="Connection closed",explanation="A previously observed network connection is no longer present.",data={**d,"action":"closed","sensor":snapshot.get("hostname")},baseline={}))
            for d in process_events:
                events.append(NetWatchEvent(workspace_id=ws.id,kind="process",severity="info",summary=f"Process {d['action']}",explanation=f"Native process lifecycle telemetry observed {d.get('name') or 'unknown'} PID {d.get('pid')} {d['action']}.",data={**d,"sensor":snapshot.get("hostname")},baseline={}))
            for d in interface_events:
                events.append(NetWatchEvent(workspace_id=ws.id,kind="interface",severity="medium" if d.get("is_up") is False else "info",summary="Interface snapshot" if d.get("periodic") else "Interface state changed",explanation=f"Interface {d.get('name')} is {'up' if d.get('is_up') else 'down'}; counters are persisted for historical comparison.",data={**d,"sensor":snapshot.get("hostname")},baseline={}))
            for metric,value in {"connection_count":snapshot.get("connection_count",0),"process_count":len(processes),"send_bps":snapshot.get("network_io",{}).get("send_bytes_per_second",0),"recv_bps":snapshot.get("network_io",{}).get("recv_bytes_per_second",0)}.items():
                await _baseline(db,ws.id,metric,value)
            if anomaly.get("status")=="anomalous":
                base=anomaly.get("baseline") or {};sample=anomaly.get("sample") or {}
                events.append(NetWatchEvent(workspace_id=ws.id,kind="anomaly",severity=anomaly.get("severity","medium"),summary="Network baseline anomaly",explanation=" ".join(anomaly.get("reasons") or ["Observed telemetry deviated from the learned baseline."]),data={**sample,"sensor":snapshot.get("hostname"),"signals":anomaly.get("reasons") or []},baseline=base))
            for event in events:
                await _correlate(db,ws.id,event);db.add(event)
        cutoff=datetime.now(timezone.utc)-timedelta(days=settings.NET_WATCH_RETENTION_DAYS)
        await db.execute(delete(NetWatchEvent).where(NetWatchEvent.created_at<cutoff));await db.commit()
    _previous_connections=current_connections;_previous_processes=processes;_previous_interfaces=interfaces
    return snapshot

async def collector_loop():
    log.info("Net-Watch history collector started interval=%ss",settings.NET_WATCH_INTERVAL_SECONDS)
    while True:
        try:await collect_once()
        except asyncio.CancelledError:raise
        except Exception:log.exception("Net-Watch history collection failed")
        await asyncio.sleep(settings.NET_WATCH_INTERVAL_SECONDS)
