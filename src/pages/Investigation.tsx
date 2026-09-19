import React, { useEffect, useMemo, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  AlertTriangle, Asset, Check, Clock3, FileJson, History, Loader2, Pin,
  Save, Server, Shield, Spline, Target, TerminalSquare, Users, X,
} from 'lucide-react';
import { cn } from '../lib/utils';
import { authHeaders } from '../lib/auth';
import { useRBAC } from '../lib/RBACProvider';

const API = (import.meta.env.VITE_PHANTOM_API_URL ?? 'http://localhost:8000').replace(/\/$/, '');

type InvestigationData = {
  finding: any;
  target: { host: string; target: string; profile: string };
  asset: any | null;
  related_findings: any[];
  related_assets: any[];
  notes: any[];
  timeline: any[];
  audit_history: any[];
  requests: any[];
  responses: any[];
};

const TABS = [
  ['timeline', 'Timeline', Clock3],
  ['evidence', 'Evidence', FileJson],
  ['notes', 'Notes', TerminalSquare],
  ['relationships', 'Relationships', Spline],
  ['payload', 'Requests / Responses', Server],
  ['remediation', 'Remediation', Shield],
  ['audit', 'Audit history', History],
] as const;

export default function Investigation() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const findingId = params.get('finding');
  const { can } = useRBAC();
  const [data, setData] = useState<InvestigationData | null>(null);
  const [activeTab, setActiveTab] = useState<string>('timeline');
  const [note, setNote] = useState('');
  const [remediation, setRemediation] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  async function load() {
    if (!findingId) return;
    setError('');
    try {
      const r = await fetch(`${API}/api/v1/investigations/${encodeURIComponent(findingId)}`, { headers: authHeaders() });
      if (!r.ok) throw new Error(await r.text());
      const value = await r.json() as InvestigationData;
      setData(value);
      setNote('');
      setRemediation(value.finding?.remediation ?? '');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to load investigation');
    }
  }

  useEffect(() => { void load(); }, [findingId]);

  async function saveNote() {
    if (!findingId || !note.trim() || !can('finding:edit')) return;
    setSaving(true);
    try {
      const r = await fetch(`${API}/api/v1/investigations/${encodeURIComponent(findingId)}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ note }),
      });
      const value = await r.json();
      if (!r.ok) throw new Error(value.detail || 'Unable to save note');
      setNote('');
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to save note');
    } finally {
      setSaving(false);
    }
  }

  async function saveRemediation() {
    if (!findingId || !can('finding:edit')) return;
    setSaving(true);
    try {
      const r = await fetch(`${API}/api/v1/investigations/${encodeURIComponent(findingId)}/remediation`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ remediation }),
      });
      const value = await r.json();
      if (!r.ok) throw new Error(value.detail || 'Unable to update remediation');
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to update remediation');
    } finally {
      setSaving(false);
    }
  }

  if (!findingId) return <EmptyInvestigation />;
  if (!data && !error) return <Loading />;
  if (error && !data) return <ErrorState error={error} />;
  const finding = data!.finding;

  return (
    <div className="flex flex-col h-full bg-phantom-bg">
      <header className="flex-none px-5 py-4 border-b border-phantom-border bg-phantom-surface flex items-center justify-between gap-4">
        <div className="flex items-center gap-3 min-w-0">
          <button onClick={() => navigate('/vulnerabilities')} className="p-2 rounded-lg hover:bg-phantom-panel text-phantom-text-tertiary"><X size={15}/></button>
          <div className="font-mono text-[10px] px-2 py-1 rounded border border-phantom-border bg-phantom-panel">INV-{finding.id.slice(0, 8)}</div>
          <div className="min-w-0">
            <h1 className="text-sm font-semibold truncate">{finding.title}</h1>
            <div className="text-[10px] text-phantom-text-tertiary mt-0.5">{data!.target.host} · {finding.module}</div>
          </div>
        </div>
        <div className="flex items-center gap-2 text-[10px] font-mono">
          <Severity value={finding.severity}/>
          <span className="px-2 py-1 rounded border border-phantom-border capitalize">{finding.status.replaceAll('_', ' ')}</span>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden">
        <aside className="w-[290px] hidden lg:block border-r border-phantom-border bg-phantom-surface/30 p-4 overflow-y-auto">
          <Section title="Finding" icon={Target}>
            <div className="p-3 border border-phantom-border bg-phantom-panel rounded-lg">
              <div className="text-sm font-medium">{finding.title}</div>
              <div className="grid grid-cols-2 gap-2 mt-3 text-[10px] font-mono text-phantom-text-tertiary">
                <span>CVSS {finding.cvss ?? '—'}</span><span>CONF {Math.round((finding.confidence ?? 0) * 100)}%</span>
                <span>CVE {finding.cve ?? '—'}</span><span>CWE {finding.cwe ?? '—'}</span>
              </div>
            </div>
          </Section>
          <Section title="Related asset" icon={Asset}>
            {data!.asset ? <div className="p-3 border border-phantom-border bg-phantom-panel rounded-lg">
              <div className="text-sm font-medium">{data!.asset.host}</div>
              <div className="text-[10px] text-phantom-text-tertiary mt-1">{data!.asset.environment} · {data!.asset.type} · {data!.asset.criticality}</div>
              <div className="mt-3 text-[10px] uppercase tracking-wider text-phantom-text-tertiary">Services</div>
              <div className="flex flex-wrap gap-1 mt-2">{(data!.asset.services ?? []).slice(0, 12).map((s: any) => <span key={`${s.protocol}-${s.port}`} className="font-mono text-[9px] px-1.5 py-0.5 rounded border border-phantom-border">{s.port}/{s.protocol}</span>)}</div>
            </div> : <EmptyText text="No asset is linked to this finding."/>}
          </Section>
          <Section title="Scan observations" icon={Clock3}>
            <div className="space-y-2">{(data!.related_findings ?? []).slice(0, 8).map((item: any) =>
              <button key={item.id} onClick={() => navigate(`/investigation?finding=${encodeURIComponent(item.id)}`)} className="w-full text-left p-2.5 border border-phantom-border rounded-md bg-phantom-panel hover:border-phantom-cyan/40">
                <div className="flex justify-between"><span className="font-mono text-[10px]">{item.scan_id.slice(0, 8)}</span><Severity value={item.severity}/></div>
                <div className="text-[10px] text-phantom-text-secondary mt-1 capitalize">{item.status.replaceAll('_', ' ')}</div>
              </button>
            )}</div>
          </Section>
        </aside>

        <main className="flex-1 flex flex-col min-w-0">
          <div className="flex overflow-x-auto border-b border-phantom-border px-3 bg-phantom-surface/30">
            {TABS.filter(([key]) => key !== 'audit' || can('audit:view')).map(([key, label, Icon]) =>
              <button key={key} onClick={() => setActiveTab(key)} className={cn('flex-none flex items-center gap-2 px-3 py-3 text-[11px] font-medium border-b-2', activeTab === key ? 'border-phantom-cyan text-phantom-text-primary' : 'border-transparent text-phantom-text-tertiary hover:text-phantom-text-secondary')}><Icon size={13}/>{label}</button>
            )}
          </div>

          <div className="flex-1 overflow-y-auto p-5 lg:p-7">
            {error && <div className="mb-4 rounded-lg border border-phantom-coral/30 bg-phantom-coral/10 px-3 py-2 text-xs text-phantom-coral">{error}</div>}
            {activeTab === 'timeline' && <Timeline items={data!.timeline}/>}
            {activeTab === 'evidence' && <Evidence finding={finding}/>}
            {activeTab === 'notes' && <Notes notes={data!.notes} note={note} setNote={setNote} save={saveNote} saving={saving} canEdit={can('finding:edit')}/>}
            {activeTab === 'relationships' && <Relationships data={data!} navigate={navigate}/>}
            {activeTab === 'payload' && <Payload requests={data!.requests} responses={data!.responses}/>}
            {activeTab === 'remediation' && <Remediation value={remediation} setValue={setRemediation} save={saveRemediation} saving={saving} canEdit={can('finding:edit')} finding={finding}/>}
            {activeTab === 'audit' && can('audit:view') && <AuditHistory items={data!.audit_history}/>}
          </div>
        </main>
      </div>
    </div>
  );
}

function Section({ title, icon: Icon, children }: any) {
  return <section className="mb-6"><h3 className="text-[10px] font-semibold text-phantom-text-tertiary uppercase tracking-wider mb-3 flex items-center gap-1.5">{Icon && <Icon size={12}/>} {title}</h3>{children}</section>;
}
function Severity({ value }: { value: string }) {
  const cls = value === 'critical' ? 'text-phantom-coral' : value === 'high' ? 'text-orange-400' : value === 'medium' ? 'text-yellow-400' : 'text-phantom-text-secondary';
  return <span className={`text-[10px] uppercase font-bold ${cls}`}>{value}</span>;
}
function EmptyText({ text }: { text: string }) { return <div className="p-3 rounded-lg border border-phantom-border text-[11px] text-phantom-text-tertiary">{text}</div>; }
function Timeline({ items }: { items: any[] }) {
  return <div className="max-w-3xl"><Header title="Investigation timeline" subtitle="Finding, asset and audited analyst activity in chronological order."/><div className="mt-5 space-y-1">{items.length ? items.map(item =>
    <div key={item.id} className="flex gap-4 py-3 border-b border-phantom-border/70">
      <div className="mt-1.5 w-2 h-2 rounded-full bg-phantom-cyan flex-none"/>
      <div className="min-w-0 flex-1"><div className="text-xs font-medium capitalize">{item.event.replaceAll('_', ' ')}</div><div className="text-[10px] font-mono text-phantom-text-tertiary mt-1">{item.at ? new Date(item.at).toLocaleString() : '—'}{item.actor ? ` · ${item.actor}` : ''}</div>{item.metadata && <pre className="text-[9px] font-mono text-phantom-text-tertiary mt-2 whitespace-pre-wrap">{JSON.stringify(item.metadata, null, 2)}</pre>}</div>
    </div>
  ) : <EmptyText text="No timeline events recorded yet."/>}</div></div>;
}
function Evidence({ finding }: { finding: any }) {
  return <div className="max-w-4xl"><Header title="Immutable scanner evidence" subtitle="Evidence is displayed from the finding record and is not replaced by analyst notes."/><div className="grid md:grid-cols-3 gap-3 mt-5">{[['Source', finding.evidence_source || 'scanner'], ['Collected', finding.evidence_collected_at ? new Date(finding.evidence_collected_at).toLocaleString() : '—'], ['SHA-256', finding.evidence_hash || '—']].map(([label, value]) => <div key={label} className="p-3 border border-phantom-border bg-phantom-surface rounded-lg"><div className="text-[9px] uppercase text-phantom-text-tertiary">{label}</div><div className="text-[10px] font-mono mt-1 break-all">{value}</div></div>)}</div><pre className="mt-3 p-4 rounded-lg border border-phantom-border bg-phantom-surface overflow-auto text-xs font-mono text-phantom-text-secondary whitespace-pre-wrap">{JSON.stringify(finding.evidence ?? {}, null, 2)}</pre></div>;
}
function Notes({ notes, note, setNote, save, saving, canEdit }: any) {
  return <div className="max-w-4xl"><Header title="Analyst notes" subtitle="Each save creates a new revision; scanner evidence remains separate."/><div className="mt-5 flex gap-2"><textarea value={note} onChange={e => setNote(e.target.value)} disabled={!canEdit} placeholder={canEdit ? 'Record reasoning, validation steps and observations…' : 'You do not have permission to edit findings.'} className="flex-1 min-h-[170px] rounded-lg border border-phantom-border bg-phantom-surface p-4 text-sm font-mono outline-none disabled:opacity-50"/><button onClick={save} disabled={saving || !canEdit || !note.trim()} className="h-9 px-3 rounded-lg border border-phantom-border bg-phantom-surface text-xs flex items-center gap-2 disabled:opacity-40"><Save size={13}/>{saving ? 'Saving…' : 'Add note'}</button></div><div className="mt-6 space-y-3">{notes.length ? notes.map((item: any) => <div key={item.id} className="p-4 border border-phantom-border bg-phantom-surface rounded-lg"><div className="flex justify-between text-[10px] text-phantom-text-tertiary font-mono"><span>{item.author_id?.slice(0, 8) || 'system'}</span><span>{item.created_at ? new Date(item.created_at).toLocaleString() : '—'}</span></div><div className="mt-3 text-xs text-phantom-text-secondary leading-relaxed whitespace-pre-wrap">{item.note}</div></div>) : <EmptyText text="No analyst notes have been recorded."/>}</div></div>;
}
function Relationships({ data, navigate }: any) {
  return <div className="max-w-5xl"><Header title="Relationships" subtitle="Context linked to this finding within the current workspace."/><div className="grid lg:grid-cols-2 gap-4 mt-5"><section className="p-4 border border-phantom-border bg-phantom-surface rounded-lg"><div className="flex items-center gap-2 text-xs font-semibold"><FileJson size={14}/> Related findings</div><div className="mt-3 space-y-2">{data.related_findings.length ? data.related_findings.map((item: any) => <button key={item.id} onClick={() => navigate(`/investigation?finding=${encodeURIComponent(item.id)}`)} className="w-full text-left p-3 rounded border border-phantom-border hover:border-phantom-cyan/40"><div className="text-xs font-medium">{item.title}</div><div className="text-[10px] text-phantom-text-tertiary mt-1">{item.scan_id.slice(0,8)} · {item.status.replaceAll('_',' ')} · {item.severity}</div></button>) : <EmptyText text="No related finding observations."/>}</div></section><section className="p-4 border border-phantom-border bg-phantom-surface rounded-lg"><div className="flex items-center gap-2 text-xs font-semibold"><Asset size={14}/> Related assets</div><div className="mt-3 space-y-2">{data.related_assets.length ? data.related_assets.map((item: any) => <div key={item.id} className="p-3 rounded border border-phantom-border"><div className="text-xs font-medium">{item.host}</div><div className="text-[10px] text-phantom-text-tertiary mt-1">{item.environment} · {item.type} · {item.criticality}</div><div className="font-mono text-[10px] mt-2 text-phantom-text-secondary">{item.target}</div></div>) : <EmptyText text="No related assets."/>}</div></section></div></div>;
}
function Payload({ requests, responses }: any) {
  return <div className="max-w-5xl"><Header title="Recorded requests & responses" subtitle="Only payloads present in finding evidence are shown; no live request is issued from this workspace."/><div className="grid lg:grid-cols-2 gap-4 mt-5"><PayloadCard title="Request" items={requests}/><PayloadCard title="Response" items={responses}/></div></div>;
}
function PayloadCard({ title, items }: any) { return <section className="border border-phantom-border bg-phantom-surface rounded-lg overflow-hidden"><div className="px-4 py-3 border-b border-phantom-border text-xs font-semibold">{title}</div>{items.map((item: any, i: number) => <pre key={i} className="p-4 text-[11px] font-mono text-phantom-text-secondary whitespace-pre-wrap overflow-auto max-h-[520px]">{JSON.stringify(item.payload ?? {}, null, 2)}</pre>)}</section>; }
function Remediation({ value, setValue, save, saving, canEdit, finding }: any) {
  return <div className="max-w-4xl"><Header title="Remediation" subtitle="Track the current remediation guidance separately from scanner evidence."/><textarea value={value} onChange={e => setValue(e.target.value)} disabled={!canEdit} className="mt-5 w-full min-h-[300px] rounded-lg border border-phantom-border bg-phantom-surface p-4 text-sm leading-relaxed outline-none disabled:opacity-50"/><div className="mt-3 flex justify-between items-center"><span className="text-[10px] text-phantom-text-tertiary">{value.length}/20000 characters · scanner baseline: {finding.remediation ? 'present' : 'none'}</span><button onClick={save} disabled={saving || !canEdit} className="h-9 px-4 rounded-lg bg-phantom-text-primary text-black text-xs font-semibold disabled:opacity-40"><Save size={13} className="inline mr-1.5"/>{saving ? 'Saving…' : 'Save remediation'}</button></div></div>;
}
function AuditHistory({ items }: { items: any[] }) { return <div className="max-w-4xl"><Header title="Audit history" subtitle="Workspace audit events associated with this finding, its scan, and its asset."/><div className="mt-5 space-y-2">{items.length ? items.map(item => <div key={item.id} className="p-3 border border-phantom-border bg-phantom-surface rounded-lg"><div className="flex justify-between gap-3"><span className="text-xs font-medium">{item.action}</span><span className="text-[10px] font-mono text-phantom-text-tertiary">{item.created_at ? new Date(item.created_at).toLocaleString() : '—'}</span></div><div className="text-[10px] text-phantom-text-tertiary mt-1">{item.actor} · {item.resource_type} · {item.resource_id?.slice(0, 12) ?? '—'}</div>{item.metadata && <pre className="mt-2 text-[9px] font-mono whitespace-pre-wrap text-phantom-text-tertiary">{JSON.stringify(item.metadata, null, 2)}</pre>}</div>) : <EmptyText text="No audit events are associated with this investigation."/>}</div></div>; }
function Header({ title, subtitle }: { title: string; subtitle: string }) { return <div><h2 className="text-sm font-semibold">{title}</h2><p className="text-xs text-phantom-text-tertiary mt-1">{subtitle}</p></div>; }
function Loading() { return <div className="h-full flex items-center justify-center text-sm text-phantom-text-tertiary"><Loader2 className="animate-spin mr-2" size={16}/>Loading investigation…</div>; }
function ErrorState({ error }: { error: string }) { return <div className="h-full flex items-center justify-center"><div className="border border-phantom-border bg-phantom-surface rounded-xl p-6 max-w-md"><AlertTriangle className="text-phantom-coral mb-3" size={20}/><div className="text-sm">{error}</div></div></div>; }
function EmptyInvestigation() { return <div className="h-full flex items-center justify-center"><div className="text-center max-w-sm"><Pin size={22} className="mx-auto text-phantom-text-tertiary mb-3"/><h2 className="text-sm font-medium">Select a finding to investigate</h2><p className="text-xs text-phantom-text-tertiary mt-2">Open a finding with <span className="font-mono">?finding=...</span> to load its investigation context.</p></div></div>; }
