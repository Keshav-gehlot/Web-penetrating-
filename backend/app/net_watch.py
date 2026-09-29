from __future__ import annotations
import asyncio, logging, socket
from datetime import datetime, timedelta, timezone
from typing import Any
import psutil
from sqlalchemy import delete, select
from .config import settings
from .database import SessionLocal
from .models import Finding, NetWatchBaseline, NetWatchEvent, Scan, Workspace

log=logging.getLogger("phantom.net_watch")
_prev_connections:set[tuple]=set();_prev_processes:dict[int,dict[str,Any]]={};_prev_interfaces:dict[str,dict[str,Any]]={};_sample_no=0

def _addr(a):
    if not a:return None
    return {"ip":getattr(a,"ip",None) or (a[0] if len(a)>0 else None),"port":getattr(a,"port",None) or (a[1] if len(a)>1 else None)}

def snapshot()->dict[str,Any]:
    connections=[]
    try:
        for c in psutil.net_connections(kind="inet"):
            l=_addr(c.laddr);r=_addr(c.raddr)
            connections.append({"pid":c.pid,"family":str(c.family),"type":str(c.type),"local":l,"remote":r,"status":c.status})
    except (psutil.AccessDenied,PermissionError) as exc:log.warning("Connection telemetry partially unavailable: %s",exc)
    processes={}
    for p in psutil.process_iter(["pid","ppid","name","username","create_time"]):
        try:processes[p.info["pid"]]=p.info
        except (psutil.NoSuchProcess,psutil.AccessDenied):continue
    stats=psutil.net_if_stats();counters=psutil.net_io_counters(pernic=True);interfaces={}
    for name,s in stats.items():
        io=counters.get(name);interfaces[name]={"isup":s.isup,"speed":s.speed,"mtu":s.mtu,"bytes_sent":getattr(io,"bytes_sent",0),"bytes_recv":getattr(io,"bytes_recv",0),"packets_sent":getattr(io,"packets_sent",0),"packets_recv":getattr(io,"packets_recv",0),"errin":getattr(io,"errin",0),"errout":getattr(io,"errout",0)}
    return {"connections":connections,"processes":processes,"interfaces":interfaces,"sensor":socket.gethostname(),"at":datetime.now(timezone.utc).isoformat()}

def _conn_key(c):return (c.get("pid"),str(c.get("local")),str(c.get("remote")),c.get("status"))
def _explain(kind,data,baseline):
    if kind=="connection":return f"Network connection state changed: {data.get('status','unknown')} from {data.get('local')} to {data.get('remote')}."
    if kind=="process":return f"Process lifecycle change observed for PID {data.get('pid')}: {data.get('name') or 'unknown process'} ({data.get('action')})."
    if kind=="interface":return f"Interface {data.get('name')} changed state or counters; current state is {'up' if data.get('isup') else 'down'}."
    return f"Current {data.get('metric')} value {data.get('value')} exceeded the learned baseline {round(float(baseline.get('mean',0)),2)}. This is a statistical deviation, not proof of compromise."

async def _baseline(db,workspace_id,metric,value):
    row=await db.scalar(select(NetWatchBaseline).where(NetWatchBaseline.workspace_id==workspace_id,NetWatchBaseline.metric==metric))
    if not row:
        row=NetWatchBaseline(workspace_id=workspace_id,metric=metric,value={"mean":float(value),"last":float(value)},sample_count=1);db.add(row);return row
    old=float((row.value or {}).get("mean",value));n=row.sample_count or 0;alpha=min(.2,2/(min(n,30)+1));mean=(1-alpha)*old+alpha*float(value)
    row.value={"mean":mean,"last":float(value)};row.sample_count=n+1;return row

async def _correlate(db,workspace_id,event):
    remote=(event.data or {}).get("remote") or {};port=remote.get("port");ip=remote.get("ip")
    if not port and not ip:return
    rows=(await db.scalars(select(Finding).join(Scan).where(Scan.workspace_id==workspace_id).order_by(Finding.last_seen.desc()).limit(500))).all()
    for f in rows:
        ev=f.evidence or {}
        if (port and str(ev.get("port",""))==str(port)) or (ip and ip in str(ev)):
            event.finding_id=f.id;return

async def collect_once():
    global _prev_connections,_prev_processes,_prev_interfaces,_sample_no
    _sample_no+=1
    snap=await asyncio.to_thread(snapshot);connections=snap["connections"];processes=snap["processes"];interfaces=snap["interfaces"]
    current_connections={_conn_key(c) for c in connections};opened=current_connections-_prev_connections if _prev_connections else set();closed=_prev_connections-current_connections if _prev_connections else set()
    conn_by_key={_conn_key(c):c for c in connections}
    proc_events=[]
    if _prev_processes:
        for pid in processes.keys()-_prev_processes.keys():proc_events.append({**processes[pid],"action":"started"})
        for pid in _prev_processes.keys()-processes.keys():proc_events.append({**_prev_processes[pid],"action":"stopped"})
    interface_events=[]
    if _prev_interfaces:
        for name,data in interfaces.items():
            old=_prev_interfaces.get(name)
            if old is None or old.get("isup")!=data.get("isup") or _sample_no%10==0:interface_events.append({"name":name,**data,"previous_isup":old.get("isup") if old else None,"periodic":bool(old and old.get("isup")==data.get("isup"))})
    async with SessionLocal() as db:
        workspaces=(await db.scalars(select(Workspace))).all()
        for ws in workspaces:
            events=[]
            for key in opened:
                d=conn_by_key[key];events.append(NetWatchEvent(workspace_id=ws.id,kind="connection",severity="info",summary="Connection opened",explanation=_explain("connection",d,{}),data={**d,"action":"opened","sensor":snap["sensor"]},baseline={}))
            for key in closed:
                d={"pid":key[0],"local":key[1],"remote":key[2],"status":key[3],"action":"closed","sensor":snap["sensor"]};events.append(NetWatchEvent(workspace_id=ws.id,kind="connection",severity="info",summary="Connection closed",explanation=_explain("connection",d,{}),data=d,baseline={}))
            for d in proc_events:events.append(NetWatchEvent(workspace_id=ws.id,kind="process",severity="info",summary=f"Process {d['action']}",explanation=_explain("process",d,{}),data={**d,"sensor":snap["sensor"]},baseline={}))
            for d in interface_events:events.append(NetWatchEvent(workspace_id=ws.id,kind="interface",severity="medium" if not d.get("isup") else "info",summary="Interface snapshot" if d.get("periodic") else "Interface state changed",explanation=_explain("interface",d,{}),data={**d,"sensor":snap["sensor"]},baseline={}))
            metrics={"connection_count":len(connections),"process_count":len(processes)}
            for metric,value in metrics.items():
                b=await _baseline(db,ws.id,metric,value);mean=float((b.value or {}).get("mean",value))
                if b.sample_count>=settings.NET_WATCH_BASELINE_MIN_SAMPLES and value>max(mean*settings.NET_WATCH_ANOMALY_MULTIPLIER,mean+10):
                    data={"metric":metric,"value":value,"sensor":snap["sensor"]};base={"mean":mean,"samples":b.sample_count}
                    events.append(NetWatchEvent(workspace_id=ws.id,kind="anomaly",severity="high",summary=f"Unusual {metric.replace('_',' ')}",explanation=_explain("anomaly",data,base),data=data,baseline=base))
            for e in events:
                await _correlate(db,ws.id,e);db.add(e)
        cutoff=datetime.now(timezone.utc)-timedelta(days=settings.NET_WATCH_RETENTION_DAYS)
        await db.execute(delete(NetWatchEvent).where(NetWatchEvent.created_at<cutoff));await db.commit()
    _prev_connections=current_connections;_prev_processes=processes;_prev_interfaces=interfaces
    return {"connections":len(connections),"processes":len(processes),"interfaces":len(interfaces)}

async def collector_loop():
    log.info("Net-Watch collector started interval=%ss retention=%sd",settings.NET_WATCH_INTERVAL_SECONDS,settings.NET_WATCH_RETENTION_DAYS)
    while True:
        try:await collect_once()
        except asyncio.CancelledError:raise
        except Exception:log.exception("Net-Watch collection failed")
        await asyncio.sleep(settings.NET_WATCH_INTERVAL_SECONDS)
