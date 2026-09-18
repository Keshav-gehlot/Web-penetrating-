import React, { useEffect, useMemo, useState } from 'react';
import { Archive, CheckCircle2, Filter, Globe2, Pencil, Plus, RefreshCw, Search, ShieldAlert, ShieldCheck, Trash2, X } from 'lucide-react';
import { authHeaders } from '../lib/auth';
import { useNavigate } from 'react-router-dom';

const API = (import.meta.env.VITE_PHANTOM_API_URL ?? 'http://localhost:8000').replace(/\/$/, '');
type Asset = {
  id: string; host: string; target: string; addresses: string[]; type: string; environment: string;
  criticality: string; owner: string | null; tags: string[]; notes: string; status: string;
  risk: string; finding_count: number; scan_count: number; last_scan: string | null;
  last_scan_status: string | null; last_seen_at: string | null; last_resolved_at: string | null;
  created_at: string | null; services?: {port:number;protocol:string;service:string|null;state:string;last_seen_at:string|null}[]; history?: {id:string;event_type:string;scan_id:string|null;metadata:Record<string,unknown>;created_at:string|null}[];
};
type Form = Pick<Asset, 'target'|'type'|'environment'|'criticality'|'owner'|'tags'|'notes'|'status'>;

const emptyForm: Form = { target: '', type: 'web', environment: 'unknown', criticality: 'medium', owner: '', tags: [], notes: '', status: 'active' };

export default function AssetManagement() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [query, setQuery] = useState('');
  const [environment, setEnvironment] = useState('all');
  const [criticality, setCriticality] = useState('all');
  const [status, setStatus] = useState('active');
  const [showForm, setShowForm] = useState(false);
  const [selected, setSelected] = useState<Asset | null>(null);
  const [editing, setEditing] = useState<Asset | null>(null);
  const [form, setForm] = useState<Form>(emptyForm);
  const [tagInput, setTagInput] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const nav = useNavigate();

  const load = async () => {
    setLoading(true); setError('');
    try {
      const params = new URLSearchParams();
      if (status !== 'all') params.set('status', status);
      if (environment !== 'all') params.set('environment', environment);
      if (criticality !== 'all') params.set('criticality', criticality);
      if (query.trim()) params.set('q', query.trim());
      const r = await fetch(`${API}/api/v1/assets?${params}`, { headers: authHeaders() });
      if (!r.ok) throw new Error(await r.text());
      setAssets(await r.json());
    } catch (e) { setError(e instanceof Error ? e.message : 'Unable to load assets'); }
    finally { setLoading(false); }
  };

  useEffect(() => { void load(); }, [status, environment, criticality, query]);

  const openCreate = () => { setEditing(null); setForm(emptyForm); setTagInput(''); setShowForm(true); setError(''); };
  const openEdit = (asset: Asset) => {
    setEditing(asset);
    setForm({ target: asset.target, type: asset.type, environment: asset.environment, criticality: asset.criticality, owner: asset.owner ?? '', tags: [...asset.tags], notes: asset.notes, status: asset.status });
    setTagInput(''); setShowForm(true); setError('');
  };

  const save = async () => {
    if (!form.target.trim()) { setError('Target is required.'); return; }
    setSaving(true); setError('');
    try {
      const url = editing ? `${API}/api/v1/assets/${encodeURIComponent(editing.id)}` : `${API}/api/v1/assets`;
      const method = editing ? 'PATCH' : 'POST';
      const payload = { target: form.target.trim(), asset_type: form.type, environment: form.environment, criticality: form.criticality, owner: form.owner.trim() || null, tags: form.tags, notes: form.notes.trim(), ...(editing ? { status: form.status } : {}) };
      const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json', ...authHeaders() }, body: JSON.stringify(payload) });
      if (!r.ok) throw new Error(await r.text());
      const saved = await r.json();
      setShowForm(false); setSelected(saved); await load();
    } catch (e) { setError(e instanceof Error ? e.message : 'Unable to save asset'); }
    finally { setSaving(false); }
  };

  const bulk = async (action: 'activate'|'deactivate'|'delete') => { if (!selectedIds.length) return; if (action === 'delete' && !window.confirm(`Delete ${selectedIds.length} selected assets? Historical scans remain preserved.`)) return; const r = await fetch(`${API}/api/v1/assets/bulk`, { method:'POST', headers:{'Content-Type':'application/json',...authHeaders()}, body:JSON.stringify({asset_ids:selectedIds,action}) }); if(!r.ok){setError(await r.text());return;} setSelectedIds([]); await load(); };
  const importInventory = () => {
    const input = document.createElement('input'); input.type = 'file'; input.accept = '.csv,text/csv';
    input.onchange = async () => { const file = input.files?.[0]; if (!file) return; const r = await fetch(`${API}/api/v1/assets/import.csv`, {method:'POST', headers:{'Content-Type':'text/csv', ...authHeaders()}, body:await file.text()}); if(!r.ok){setError(await r.text());return;} await load(); };
    input.click();
  };
  const exportInventory = async () => { const r=await fetch(`${API}/api/v1/assets/export.csv`,{headers:authHeaders()}); if(!r.ok){setError(await r.text());return;} const blob=await r.blob(); const url=URL.createObjectURL(blob); const a=document.createElement('a'); a.href=url; a.download='phantom-assets.csv'; a.click(); URL.revokeObjectURL(url); };

  const remove = async (asset: Asset) => {
    if (!window.confirm(`Delete ${asset.host} from the workspace inventory? Historical scans will be preserved.`)) return;
    const r = await fetch(`${API}/api/v1/assets/${encodeURIComponent(asset.id)}`, { method: 'DELETE', headers: authHeaders() });
    if (!r.ok) { setError(await r.text()); return; }
    if (selected?.id === asset.id) setSelected(null);
    await load();
  };

  const resolve = async (asset: Asset) => {
    setError('');
    try {
      const r = await fetch(`${API}/api/v1/assets/${encodeURIComponent(asset.id)}/resolve`, { method: 'POST', headers: authHeaders() });
      if (!r.ok) throw new Error(await r.text());
      setSelected(await r.json()); await load();
    } catch (e) { setError(e instanceof Error ? e.message : 'Unable to resolve asset'); }
  };

  const counts = useMemo(() => ({
    total: assets.length,
    critical: assets.filter(a => a.criticality === 'critical').length,
    exposed: assets.filter(a => a.risk === 'high' || a.risk === 'critical').length,
    scanned: assets.filter(a => a.last_scan).length,
  }), [assets]);

  return <div className="flex flex-col h-full bg-phantom-bg">
    <header className="flex-none border-b border-phantom-border bg-phantom-surface/70 px-6 py-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div><div className="text-[10px] font-mono uppercase tracking-[0.18em] text-phantom-cyan mb-2">Attack surface inventory</div><h1 className="text-xl font-semibold tracking-tight">Assets</h1><p className="text-sm text-phantom-text-secondary mt-1 max-w-2xl">The authoritative inventory of systems PHANTOM is permitted to assess.</p></div>
        <div className="flex gap-2"><button onClick={() => void load()} className="h-9 px-3 border border-phantom-border rounded-lg text-xs flex items-center gap-2 hover:bg-phantom-panel"><RefreshCw size={13}/>Refresh</button><button onClick={openCreate} className="h-9 px-3 rounded-lg bg-phantom-text-primary text-black text-xs font-semibold flex items-center gap-2"><Plus size={13}/>Add asset</button></div>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 mt-5">
        <Metric label="Inventory" value={counts.total} icon={Globe2}/><Metric label="Criticality: critical" value={counts.critical} icon={ShieldAlert}/><Metric label="High / critical risk" value={counts.exposed} icon={ShieldAlert}/><Metric label="Scanned" value={counts.scanned} icon={CheckCircle2}/>
      </div>
      <div className="flex flex-wrap items-center gap-2 mt-4"><button onClick={importInventory} className="h-9 px-3 border border-phantom-border rounded-lg text-xs">Import CSV</button><button onClick={()=>void exportInventory()} className="h-9 px-3 border border-phantom-border rounded-lg text-xs">Export CSV</button>{selectedIds.length>0&&<><button onClick={()=>void bulk("activate")} className="h-9 px-3 border border-phantom-border rounded-lg text-xs">Activate ({selectedIds.length})</button><button onClick={()=>void bulk("deactivate")} className="h-9 px-3 border border-phantom-border rounded-lg text-xs">Deactivate</button><button onClick={()=>void bulk("delete")} className="h-9 px-3 border border-phantom-coral/30 text-phantom-coral rounded-lg text-xs">Delete</button></>}</div><div className="flex flex-wrap items-center gap-2 mt-2">
        <div className="relative flex-1 min-w-[220px] max-w-lg"><Search className="absolute left-3 top-1/2 -translate-y-1/2 text-phantom-text-tertiary" size={14}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search host, target, or owner…" className="w-full h-9 bg-phantom-panel border border-phantom-border rounded-lg pl-9 pr-3 text-xs outline-none focus:border-phantom-cyan"/></div>
        <Select value={status} onChange={setStatus} options={['all','active','inactive']} label="Status"/><Select value={environment} onChange={setEnvironment} options={['all','production','staging','development','internal','unknown']} label="Environment"/><Select value={criticality} onChange={setCriticality} options={['all','critical','high','medium','low']} label="Criticality"/>
        <span className="h-9 px-3 border border-phantom-border rounded-lg flex items-center gap-2 text-[11px] text-phantom-text-tertiary"><Filter size={13}/>{assets.length} shown</span>
      </div>
      {error && <div className="mt-3 rounded-lg border border-phantom-coral/25 bg-phantom-coral/5 px-3 py-2 text-xs text-phantom-coral">{error}</div>}
    </header>

    <main className="flex-1 overflow-auto p-6">
      <div className="border border-phantom-border rounded-xl bg-phantom-surface overflow-hidden">
        <table className="w-full text-left">
          <thead><tr className="border-b border-phantom-border bg-phantom-panel/50"><th className="px-4 py-3"><input type="checkbox" aria-label="Select all visible assets" checked={assets.length>0&&selectedIds.length===assets.length} onChange={e=>setSelectedIds(e.target.checked?assets.map(a=>a.id):[])}/></th>
            {['Asset','Classification','Exposure','Risk','Activity',''].map((h,i)=><th key={i} className="px-4 py-3 text-[10px] uppercase tracking-wider text-phantom-text-tertiary">{h}</th>)}
          </tr></thead>
          <tbody>
            {loading ? <tr><td colSpan={7} className="p-12 text-center text-sm text-phantom-text-tertiary">Loading inventory…</td></tr> :
            assets.length === 0 ? <tr><td colSpan={7} className="p-12 text-center"><Archive size={22} className="mx-auto text-phantom-text-tertiary"/><div className="mt-3 text-sm">No assets match the current filters.</div><div className="mt-1 text-xs text-phantom-text-tertiary">Add an authorized target or adjust the filters.</div></td></tr> :
            assets.map(a => <tr key={a.id} className="border-b border-phantom-border last:border-0 hover:bg-phantom-panel-hover">
              <td className="px-4 py-3"><input type="checkbox" aria-label={`Select ${a.host}`} checked={selectedIds.includes(a.id)} onChange={e=>setSelectedIds(v=>e.target.checked?[...new Set([...v,a.id])]:v.filter(id=>id!==a.id))}/></td><td className="px-4 py-3 min-w-[260px]"><button onClick={async () => { try { const r = await fetch(`${API}/api/v1/assets/${encodeURIComponent(a.id)}`, {headers:authHeaders()}); if (r.ok) { const detail=await r.json(); const fr=await fetch(`${API}/api/v1/assets/${encodeURIComponent(a.id)}/findings`,{headers:authHeaders()}); detail.findings=fr.ok?await fr.json():[]; setSelected(detail); } else setSelected(a); } catch { setSelected(a); } }} className="text-sm font-medium hover:text-phantom-cyan">{a.host}</button><div className="text-[10px] text-phantom-text-tertiary font-mono mt-1 truncate max-w-[320px]">{a.target}</div><div className="flex gap-1 mt-2">{a.tags.slice(0,3).map(t=><span key={t} className="text-[9px] px-1.5 py-0.5 rounded border border-phantom-border bg-phantom-panel">{t}</span>)}</div></td>
              <td className="px-4 py-3"><div className="text-xs">{a.environment}</div><div className="text-[10px] text-phantom-text-tertiary mt-1">{a.type} · {a.criticality}</div></td>
              <td className="px-4 py-3"><div className="font-mono text-xs">{a.addresses[0] ?? 'unresolved'}</div><div className="text-[10px] text-phantom-text-tertiary mt-1">{a.addresses.length} address{a.addresses.length === 1 ? '' : 'es'}</div></td>
              <td className="px-4 py-3"><RiskBadge risk={a.risk}/></td>
              <td className="px-4 py-3"><div className="text-xs">{a.last_scan ? new Date(a.last_scan).toLocaleString() : 'Never scanned'}</div><div className="text-[10px] text-phantom-text-tertiary mt-1">{a.finding_count} finding{a.finding_count === 1 ? '' : 's'} · {a.scan_count} recent scan{a.scan_count === 1 ? '' : 's'}</div></td>
              <td className="px-4 py-3"><div className="flex justify-end gap-1"><button title="Edit asset" onClick={() => openEdit(a)} className="p-2 text-phantom-text-tertiary hover:text-phantom-cyan"><Pencil size={14}/></button><button title="Delete asset" onClick={() => void remove(a)} className="p-2 text-phantom-text-tertiary hover:text-phantom-coral"><Trash2 size={14}/></button></div></td>
            </tr>)}
          </tbody>
        </table>
      </div>
    </main>

    {selected && <aside className="fixed right-0 top-0 bottom-0 w-full max-w-md bg-phantom-surface border-l border-phantom-border shadow-2xl z-30 overflow-auto"><div className="p-5 border-b border-phantom-border flex items-start justify-between"><div><div className="text-[10px] font-mono uppercase tracking-wider text-phantom-cyan">Asset detail</div><h2 className="text-lg font-semibold mt-1">{selected.host}</h2><div className="text-[11px] font-mono text-phantom-text-tertiary mt-1 break-all">{selected.target}</div></div><button onClick={() => setSelected(null)} className="p-2 text-phantom-text-tertiary hover:text-phantom-text-primary"><X size={16}/></button></div>
      <div className="p-5 space-y-5"><div className="grid grid-cols-2 gap-2"><Detail label="Status" value={selected.status}/><Detail label="Environment" value={selected.environment}/><Detail label="Type" value={selected.type}/><Detail label="Criticality" value={selected.criticality}/><Detail label="Risk" value={selected.risk}/><Detail label="Owner" value={selected.owner ?? 'Unassigned'}/></div>
        <div><Label text="Resolved addresses"/><div className="mt-2 space-y-1">{selected.addresses.length ? selected.addresses.map(ip=><div key={ip} className="font-mono text-xs rounded border border-phantom-border bg-phantom-panel px-3 py-2">{ip}</div>) : <div className="text-xs text-phantom-text-tertiary">No public address resolved.</div>}</div>
        <div><Label text="Observed services"/><div className="mt-2 space-y-1">{selected.services?.length ? selected.services.map(s=><div key={`${s.protocol}-${s.port}`} className="flex items-center justify-between rounded border border-phantom-border bg-phantom-panel px-3 py-2 text-xs"><span className="font-mono">{s.port}/{s.protocol}</span><span className="text-phantom-text-secondary">{s.service ?? 'unknown'} · {s.state}</span></div>) : <span className="text-xs text-phantom-text-tertiary">No discovered services yet.</span>}</div></div><div><Label text="Asset activity"/><div className="mt-2 space-y-2">{selected.history?.slice(0,8).map(h=><div key={h.id} className="text-xs"><span className="font-mono text-phantom-cyan">{h.event_type}</span><span className="text-phantom-text-tertiary ml-2">{formatDate(h.created_at)}</span></div>)}</div></div><div><Label text="Linked findings"/><div className="mt-2 space-y-1">{selected.findings?.length ? selected.findings.slice(0,8).map(f=><button key={f.id} onClick={()=>nav(`/vulnerabilities?finding=${encodeURIComponent(f.id)}`)} className="w-full text-left rounded border border-phantom-border bg-phantom-panel px-3 py-2 text-xs hover:border-phantom-cyan"><span className="font-medium">{f.title}</span><span className="float-right uppercase text-[9px] text-phantom-text-tertiary">{f.severity}</span></button>) : <span className="text-xs text-phantom-text-tertiary">No linked findings.</span>}</div></div><div><Label text="Tags"/><div className="flex flex-wrap gap-1.5 mt-2">{selected.tags.length ? selected.tags.map(t=><span key={t} className="text-[10px] px-2 py-1 rounded border border-phantom-border bg-phantom-panel">{t}</span>) : <span className="text-xs text-phantom-text-tertiary">No tags.</span>}</div></div>
        <div><Label text="Notes"/><p className="text-xs text-phantom-text-secondary mt-2 whitespace-pre-wrap">{selected.notes || 'No notes recorded.'}</p></div>
        <div className="grid grid-cols-2 gap-2"><Detail label="Findings" value={String(selected.finding_count)}/><Detail label="Scans" value={String(selected.scan_count)}/><Detail label="Last seen" value={formatDate(selected.last_seen_at)}/><Detail label="Last resolved" value={formatDate(selected.last_resolved_at)}/></div>
        <div className="flex flex-wrap gap-2"><button onClick={() => nav(`/scans?target=${encodeURIComponent(selected.target)}`)} className="h-9 px-3 rounded-lg bg-phantom-text-primary text-black text-xs font-semibold">Start assessment</button><button onClick={() => void resolve(selected)} className="h-9 px-3 rounded-lg border border-phantom-border text-xs flex items-center gap-2"><RefreshCw size={13}/>Resolve DNS</button><button onClick={() => openEdit(selected)} className="h-9 px-3 rounded-lg border border-phantom-border text-xs flex items-center gap-2"><Pencil size={13}/>Edit</button></div>
      </div></aside>}

    {showForm && <div className="fixed inset-0 z-40 bg-black/40 flex items-start justify-center p-6 overflow-auto"><div className="w-full max-w-2xl bg-phantom-surface border border-phantom-border rounded-xl shadow-2xl"><div className="p-5 border-b border-phantom-border flex items-center justify-between"><div><div className="text-[10px] font-mono uppercase tracking-wider text-phantom-cyan">{editing ? 'Edit inventory record' : 'Onboard asset'}</div><h2 className="text-lg font-semibold mt-1">{editing ? editing.host : 'New asset'}</h2></div><button onClick={() => setShowForm(false)} className="p-2 text-phantom-text-tertiary"><X size={16}/></button></div><div className="p-5 grid md:grid-cols-2 gap-4">
      <div className="md:col-span-2"><Label text="Authorized target"/><input value={form.target} onChange={e => setForm(f => ({...f,target:e.target.value}))} placeholder="https://example.com" className="control mt-2 w-full"/><div className="text-[10px] text-phantom-text-tertiary mt-1">The target must already be inside the workspace Scope Manager policy.</div></div>
      <Field label="Asset type"><Select value={form.type} onChange={v => setForm(f=>({...f,type:v}))} options={['web','api','domain','host','service']} label="Type"/></Field>
      <Field label="Environment"><Select value={form.environment} onChange={v => setForm(f=>({...f,environment:v}))} options={['unknown','production','staging','development','internal']} label="Environment"/></Field>
      <Field label="Criticality"><Select value={form.criticality} onChange={v => setForm(f=>({...f,criticality:v}))} options={['critical','high','medium','low']} label="Criticality"/></Field>
      {editing && <Field label="Lifecycle status"><Select value={form.status} onChange={v => setForm(f=>({...f,status:v}))} options={['active','inactive']} label="Status"/></Field>}
      <Field label="Owner"><input value={form.owner ?? ''} onChange={e=>setForm(f=>({...f,owner:e.target.value}))} placeholder="team@example.com or Security" className="control mt-2 w-full"/></Field>
      <div><Label text="Tags"/><div className="flex gap-2 mt-2"><input value={tagInput} onChange={e=>setTagInput(e.target.value)} onKeyDown={e=>{if(e.key==='Enter'&&tagInput.trim()){setForm(f=>({...f,tags:[...new Set([...f.tags,tagInput.trim()])]}));setTagInput('')}}} placeholder="production" className="control flex-1"/><button onClick={()=>{if(tagInput.trim()){setForm(f=>({...f,tags:[...new Set([...f.tags,tagInput.trim()])]}));setTagInput('')}}} className="iconButton"><Plus size={14}/></button></div><div className="flex flex-wrap gap-1.5 mt-2">{form.tags.map(t=><button key={t} onClick={()=>setForm(f=>({...f,tags:f.tags.filter(x=>x!==t)}))} className="text-[10px] px-2 py-1 rounded border border-phantom-border bg-phantom-panel">{t} ×</button>)}</div></div>
      <div className="md:col-span-2"><Label text="Operational notes"/><textarea value={form.notes} onChange={e=>setForm(f=>({...f,notes:e.target.value}))} rows={4} placeholder="Ownership, business context, assessment notes…" className="control mt-2 w-full resize-y"/></div>
    </div><div className="px-5 py-4 border-t border-phantom-border flex justify-end gap-2"><button onClick={()=>setShowForm(false)} className="h-9 px-3 rounded-lg border border-phantom-border text-xs">Cancel</button><button onClick={()=>void save()} disabled={saving||!form.target.trim()} className="h-9 px-4 rounded-lg bg-phantom-text-primary text-black text-xs font-semibold disabled:opacity-40">{saving?'Saving…':editing?'Save changes':'Onboard asset'}</button></div></div></div>}
  </div>;
}

function Metric({label,value,icon:Icon}:{label:string;value:number;icon:React.ComponentType<{size?:number}>}){return <div className="border border-phantom-border rounded-lg bg-phantom-panel px-3 py-2 flex items-center gap-3"><Icon size={14} className="text-phantom-cyan"/><div><div className="text-[10px] text-phantom-text-tertiary">{label}</div><div className="text-sm font-mono mt-0.5">{value}</div></div></div>}
function Select({value,onChange,options,label}:{value:string;onChange:(v:string)=>void;options:string[];label:string}){return <select aria-label={label} value={value} onChange={e=>onChange(e.target.value)} className="h-9 px-3 bg-phantom-panel border border-phantom-border rounded-lg text-xs outline-none">{options.map(o=><option key={o} value={o}>{o[0].toUpperCase()+o.slice(1)}</option>)}</select>}
function Field({label,children}:{label:string;children:React.ReactNode}){return <div><Label text={label}/>{children}</div>}
function Label({text}:{text:string}){return <div className="text-[10px] uppercase tracking-wider text-phantom-text-tertiary">{text}</div>}
function Detail({label,value}:{label:string;value:string}){return <div className="rounded-lg border border-phantom-border bg-phantom-panel p-3"><div className="text-[10px] text-phantom-text-tertiary">{label}</div><div className="text-xs font-medium mt-1 truncate">{value}</div></div>}
function formatDate(value:string|null){return value?new Date(value).toLocaleString():'—'}
function RiskBadge({risk}:{risk:string}){const critical=risk==='critical',high=risk==='high';return <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded border text-[10px] uppercase ${critical?'text-phantom-coral border-phantom-coral/20 bg-phantom-coral/10':high?'text-phantom-amber border-phantom-amber/20 bg-phantom-amber/10':'text-phantom-text-secondary border-phantom-border bg-phantom-panel'}`}>{critical||high?<ShieldAlert size={11}/>:<ShieldCheck size={11}/>} {risk}</span>}
