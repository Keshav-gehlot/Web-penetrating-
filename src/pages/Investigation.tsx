import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Target, MessageSquare, Pin, TerminalSquare, Play, Spline, FileJson, Clock3, Save, Loader2, AlertTriangle } from 'lucide-react';
import { cn } from '../lib/utils';

const API = (import.meta.env.VITE_PHANTOM_API_URL ?? 'http://localhost:8000').replace(/\/$/, '');

type InvestigationData = {
  finding: any; target: { host: string; target: string; profile: string };
  history: any[]; timeline: any[];
};

export default function Investigation() {
  const [params] = useSearchParams();
  const findingId = params.get('finding');
  const [data, setData] = useState<InvestigationData | null>(null);
  const [activeTab, setActiveTab] = useState('notes');
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!findingId) return;
    setError('');
    fetch(`${API}/api/v1/investigations/${encodeURIComponent(findingId)}`)
      .then(async (r) => { if (!r.ok) throw new Error(await r.text()); return r.json(); })
      .then((value: InvestigationData) => { setData(value); setNote(value.finding.evidence?.analyst_note ?? ''); })
      .catch((e) => setError(e.message || 'Unable to load investigation'));
  }, [findingId]);

  async function saveNote() {
    if (!findingId) return;
    setSaving(true); setError('');
    try {
      const r = await fetch(`${API}/api/v1/investigations/${encodeURIComponent(findingId)}/notes`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ note }) });
      if (!r.ok) throw new Error(await r.text());
    } catch (e) { setError(e instanceof Error ? e.message : 'Unable to save note'); }
    finally { setSaving(false); }
  }

  if (!findingId) return <EmptyInvestigation />;
  if (!data && !error) return <div className="h-full flex items-center justify-center text-sm text-phantom-text-tertiary"><Loader2 className="animate-spin mr-2" size={16}/>Loading investigation…</div>;
  if (error && !data) return <div className="h-full flex items-center justify-center"><div className="border border-phantom-border bg-phantom-surface rounded-xl p-6 max-w-md"><AlertTriangle className="text-phantom-coral mb-3" size={20}/><div className="text-sm">{error}</div></div></div>;

  const finding = data!.finding;
  return (
    <div className="flex flex-col h-full bg-phantom-bg">
      <div className="flex-none p-4 border-b border-phantom-border bg-phantom-surface flex items-center justify-between">
        <div className="flex items-center gap-4 min-w-0"><div className="font-mono text-[10px] px-2 py-1 bg-phantom-panel border border-phantom-border rounded text-phantom-text-secondary">INV-{finding.id.slice(0, 8)}</div><h1 className="text-sm font-medium truncate">Investigation Workspace</h1></div>
        <div className="text-[11px] font-mono text-phantom-text-tertiary">{finding.status.replace('_', ' ').toUpperCase()}</div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        <aside className="w-[300px] border-r border-phantom-border bg-phantom-surface/30 p-4 overflow-y-auto">
          <Section title="Investigation Target" icon={Target}><div className="p-3 border border-phantom-border bg-phantom-panel rounded-lg"><div className="text-sm font-medium truncate">{data!.target.host}</div><div className="text-[11px] font-mono text-phantom-text-secondary mt-1 truncate">{data!.target.target}</div><div className="text-[10px] uppercase tracking-wider text-phantom-text-tertiary mt-3">{data!.target.profile} profile</div></div></Section>
          <Section title="Finding"><div className="p-3 border border-phantom-border bg-phantom-panel rounded-lg"><div className="flex items-center gap-2 mb-2"><Severity value={finding.severity}/><span className="font-mono text-[10px] text-phantom-text-tertiary">{finding.id.slice(0, 8)}</span></div><div className="text-sm font-medium leading-snug">{finding.title}</div><div className="grid grid-cols-2 gap-2 mt-3 text-[10px] font-mono text-phantom-text-tertiary"><span>CVSS {finding.cvss ?? '—'}</span><span>CONF {Math.round((finding.confidence ?? 0) * 100)}%</span></div></div></Section>
          <Section title="Scan history" icon={Clock3}><div className="space-y-2">{data!.history.map((h) => <div key={h.id} className="p-2.5 border border-phantom-border rounded-md bg-phantom-panel"><div className="flex justify-between text-[10px] font-mono"><span>{h.scan_id.slice(0, 8)}</span><Severity value={h.severity}/></div><div className="text-[11px] text-phantom-text-secondary mt-1 capitalize">{h.status.replace('_', ' ')}</div></div>)}</div></Section>
        </aside>

        <main className="flex-1 flex flex-col min-w-0">
          <div className="flex border-b border-phantom-border px-4 pt-2 gap-4 bg-phantom-surface/30">
            <Tab label="Analyst Scratchpad" active={activeTab === 'notes'} onClick={() => setActiveTab('notes')} icon={TerminalSquare}/>
            <Tab label="Evidence" active={activeTab === 'evidence'} onClick={() => setActiveTab('evidence')} icon={FileJson}/>
            <Tab label="Timeline" active={activeTab === 'timeline'} onClick={() => setActiveTab('timeline')} icon={Clock3}/>
            <Tab label="Request / Response" active={activeTab === 'payload'} onClick={() => setActiveTab('payload')} icon={Spline}/>
          </div>
          <div className="flex-1 overflow-y-auto p-6">
            {activeTab === 'notes' && <div className="max-w-3xl"><div className="flex items-center justify-between mb-3"><div><h2 className="text-sm font-medium">Analyst notes</h2><p className="text-xs text-phantom-text-tertiary mt-1">Notes are persisted with this finding for the current workspace.</p></div><button onClick={saveNote} disabled={saving} className="h-8 px-3 rounded-md border border-phantom-border bg-phantom-surface text-xs flex items-center gap-2 hover:border-phantom-border-strong">{saving ? <Loader2 size={13} className="animate-spin"/> : <Save size={13}/>} Save</button></div><textarea value={note} onChange={(e) => setNote(e.target.value)} className="w-full min-h-[430px] rounded-lg border border-phantom-border bg-phantom-surface p-4 outline-none text-sm font-mono leading-relaxed focus:border-phantom-cyan" placeholder="Record evidence, reasoning, validation steps and remediation notes…"/></div>}
            {activeTab === 'evidence' && <Evidence evidence={finding.evidence}/>} 
            {activeTab === 'timeline' && <Timeline items={data!.timeline}/>} 
            {activeTab === 'payload' && <Payload evidence={finding.evidence}/>} 
          </div>
        </main>

        <aside className="hidden xl:block w-[310px] border-l border-phantom-border bg-phantom-surface/20 p-4 overflow-y-auto"><h3 className="text-xs uppercase tracking-wider text-phantom-text-tertiary mb-3">Remediation</h3><div className="p-4 border border-phantom-border rounded-lg bg-phantom-panel text-xs text-phantom-text-secondary leading-relaxed">{finding.remediation || 'No remediation guidance was recorded for this finding.'}</div><h3 className="text-xs uppercase tracking-wider text-phantom-text-tertiary mt-6 mb-3">Description</h3><div className="text-xs text-phantom-text-secondary leading-relaxed">{finding.description || 'No description was recorded.'}</div></aside>
      </div>
    </div>
  );
}

function Section({ title, icon: Icon, children }: any) { return <section className="mb-6"><h3 className="text-[10px] font-semibold text-phantom-text-tertiary uppercase tracking-wider mb-3 flex items-center gap-1.5">{Icon && <Icon size={12}/>} {title}</h3>{children}</section>; }
function Severity({ value }: { value: string }) { return <span className={cn('text-[10px] uppercase font-bold', value === 'critical' ? 'text-phantom-coral' : value === 'high' ? 'text-orange-400' : value === 'medium' ? 'text-yellow-400' : 'text-phantom-text-secondary')}>{value}</span>; }
function Tab({ label, active, onClick, icon: Icon }: any) { return <button onClick={onClick} className={cn('flex items-center gap-2 px-3 py-2 text-xs font-medium border-b-2 mb-[-1px]', active ? 'border-phantom-cyan text-phantom-text-primary' : 'border-transparent text-phantom-text-tertiary hover:text-phantom-text-secondary')}><Icon size={14}/>{label}</button>; }
function Evidence({ evidence }: any) { return <pre className="max-w-4xl p-4 rounded-lg border border-phantom-border bg-phantom-surface overflow-auto text-xs font-mono text-phantom-text-secondary whitespace-pre-wrap">{JSON.stringify(evidence ?? {}, null, 2)}</pre>; }
function Timeline({ items }: any) { return <div className="max-w-2xl space-y-3">{items.map((item: any, i: number) => <div key={i} className="flex gap-3"><div className="mt-1.5 w-2 h-2 rounded-full bg-phantom-cyan flex-none"/><div className="border-b border-phantom-border pb-3 flex-1"><div className="text-xs font-medium">{item.event.replaceAll('_', ' ')}</div><div className="text-[10px] font-mono text-phantom-text-tertiary mt-1">{item.at ?? '—'}</div></div></div>)}</div>; }
function Payload({ evidence }: any) { return <div className="grid lg:grid-cols-2 gap-4"><div className="border border-phantom-border rounded-lg bg-phantom-surface min-h-[300px] p-4"><div className="text-xs font-medium mb-3">Recorded request</div><pre className="text-xs font-mono text-phantom-text-secondary whitespace-pre-wrap">{JSON.stringify(evidence?.request ?? evidence?.url ?? 'No request evidence recorded.', null, 2)}</pre></div><div className="border border-phantom-border rounded-lg bg-phantom-surface min-h-[300px] p-4"><div className="text-xs font-medium mb-3">Recorded response</div><pre className="text-xs font-mono text-phantom-text-secondary whitespace-pre-wrap">{JSON.stringify(evidence?.response ?? 'No response evidence recorded.', null, 2)}</pre></div></div>; }
function EmptyInvestigation() { return <div className="h-full flex items-center justify-center"><div className="text-center max-w-sm"><Pin size={22} className="mx-auto text-phantom-text-tertiary mb-3"/><h2 className="text-sm font-medium">Select a finding to investigate</h2><p className="text-xs text-phantom-text-tertiary mt-2">Open a finding with <span className="font-mono">?finding=...</span> to load its investigation context.</p></div></div>; }
