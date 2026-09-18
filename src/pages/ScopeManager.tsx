import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Check, ChevronRight, CircleHelp, Globe2, LockKeyhole, Plus, RefreshCw, Save, ShieldCheck, X } from 'lucide-react';
import { approveScope, checkScopeTarget, getScope, rejectScope, saveScope, type WorkspaceScope } from '../lib/scopeApi';

const emptyScope: WorkspaceScope = {
  id: null, workspace_id: null, configured: false, enabled: false,
  authorized_targets: [], excluded_targets: [], allowed_ports: [80, 443], allowed_paths: ['/'], blocked_paths: [],
  max_requests: 250, max_concurrency: 1, max_redirects: 3,
  approval_status: 'pending', approved_at: null, approved_by: null, approval_comment: null,
  authorization_acknowledged: false, authorization_acknowledged_at: null, acknowledged_by: null,
  created_at: null, updated_at: null,
  effective_limits: { max_requests: 250, max_concurrency: 1, max_redirects: 3 },
};

type Draft = Omit<WorkspaceScope, 'id' | 'workspace_id' | 'configured' | 'authorization_acknowledged_at' | 'acknowledged_by' | 'created_at' | 'updated_at' | 'effective_limits' | 'approval_status' | 'approved_at' | 'approved_by' | 'approval_comment'> & { authorization_reconfirmed: boolean };

export default function ScopeManager() {
  const [scope, setScope] = useState<WorkspaceScope>(emptyScope);
  const [draft, setDraft] = useState<Draft>(toDraft(emptyScope));
  const [targetInput, setTargetInput] = useState('');
  const [excludedInput, setExcludedInput] = useState('');
  const [allowedPathInput, setAllowedPathInput] = useState('');
  const [blockedPathInput, setBlockedPathInput] = useState('');
  const [portInput, setPortInput] = useState('');
  const [checkInput, setCheckInput] = useState('');
  const [checkResult, setCheckResult] = useState<{ allowed: boolean; host?: string; port?: number; reason?: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [checking, setChecking] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [approvalComment, setApprovalComment] = useState('');
  const [approvalBusy, setApprovalBusy] = useState(false);

  const load = async () => {
    setLoading(true); setError(''); setMessage('');
    try { const value = await getScope(); setScope(value); setDraft(toDraft(value)); setCheckResult(null); }
    catch (e) { setError(errorText(e, 'Unable to load workspace scope')); }
    finally { setLoading(false); }
  };
  useEffect(() => { void load(); }, []);

  const dirty = useMemo(() => JSON.stringify(draft) !== JSON.stringify(toDraft(scope)), [draft, scope]);
  const validationIssues = useMemo(() => validateDraft(draft), [draft]);
  const canEnable = draft.authorization_acknowledged && draft.authorized_targets.length > 0;
  const updatePolicy = (updater: (current: Draft) => Draft) => {
    setDraft(current => {
      const next = updater(current);
      const materialChanged =
        JSON.stringify(current.authorized_targets) !== JSON.stringify(next.authorized_targets) ||
        JSON.stringify(current.excluded_targets) !== JSON.stringify(next.excluded_targets) ||
        JSON.stringify(current.allowed_ports) !== JSON.stringify(next.allowed_ports) ||
        JSON.stringify(current.allowed_paths) !== JSON.stringify(next.allowed_paths) ||
        JSON.stringify(current.blocked_paths) !== JSON.stringify(next.blocked_paths) ||
        current.max_requests !== next.max_requests ||
        current.max_concurrency !== next.max_concurrency ||
        current.max_redirects !== next.max_redirects;
      return materialChanged && scope.configured
        ? { ...next, authorization_acknowledged: false, authorization_reconfirmed: false }
        : next;
    });
    setCheckResult(null);
    setMessage('');
  };
  useEffect(() => {
    if (!dirty) return;
    const handler = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [dirty]);

  const refresh = async () => {
    if (dirty && !window.confirm('Discard unsaved scope changes?')) return;
    await load();
  };
  const add = (key: 'authorized_targets' | 'excluded_targets' | 'allowed_paths' | 'blocked_paths', value: string, clear: () => void) => {
    const values = value.split(/[\n,]/).map(x => x.trim()).filter(Boolean);
    if (!values.length) return;
    updatePolicy(current => ({ ...current, [key]: unique([...current[key], ...values]) }));
    clear(); setError('');
  };
  const remove = (key: 'authorized_targets' | 'excluded_targets' | 'allowed_paths' | 'blocked_paths', value: string) => {
    updatePolicy(current => ({ ...current, [key]: current[key].filter(x => x !== value) }));
  };
  const addPort = () => {
    const port = Number(portInput.trim());
    if (!Number.isInteger(port) || port < 1 || port > 65535) { setError('Ports must be integers between 1 and 65535.'); return; }
    updatePolicy(current => ({ ...current, allowed_ports: uniqueNumbers([...current.allowed_ports, port]).sort((a, b) => a - b) }));
    setPortInput(''); setError('');
  };
  const save = async () => {
    if (validationIssues.length) { setError(validationIssues[0]); return; }
    if (draft.enabled && !canEnable) { setError('To enable scope, add at least one authorized target and acknowledge authorization.'); return; }
    setSaving(true); setError(''); setMessage('');
    try { const value = await saveScope(draft); setScope(value); setDraft(toDraft(value)); setCheckResult(null); setMessage('Scope policy saved.'); }
    catch (e) { setError(errorText(e, 'Unable to save scope')); }
    finally { setSaving(false); }
  };
  const changeApproval = async (approve: boolean) => {
    setApprovalBusy(true); setError(''); setMessage('');
    try {
      const value = approve ? await approveScope(approvalComment) : await rejectScope(approvalComment);
      setScope(value); setDraft(toDraft(value)); setApprovalComment('');
      setMessage(approve ? 'Scope approved. Scans may execute under the approved policy.' : 'Scope approval rejected. Scans remain blocked until approval is granted.');
    } catch (e) {
      setError(errorText(e, approve ? 'Unable to approve scope' : 'Unable to reject scope'));
    } finally { setApprovalBusy(false); }
  };

  const check = async () => {
    if (!checkInput.trim()) return;
    setChecking(true); setCheckResult(null); setError('');
    try { setCheckResult(await checkScopeTarget(checkInput.trim())); }
    catch (e) { setError(errorText(e, 'Scope check failed')); }
    finally { setChecking(false); }
  };

  if (loading) return <div className="h-full flex items-center justify-center text-sm text-phantom-text-tertiary">Loading workspace scope…</div>;

  return <div className="h-full overflow-auto bg-phantom-bg">
    <header className="sticky top-0 z-10 border-b border-phantom-border bg-phantom-bg/95 backdrop-blur px-6 py-5">
      <div className="max-w-6xl mx-auto flex flex-wrap items-start justify-between gap-4">
        <div><div className="text-[10px] font-mono uppercase tracking-[0.18em] text-phantom-cyan mb-2">Assessment governance</div><h1 className="text-xl font-semibold tracking-tight">Scope Manager</h1><p className="text-sm text-phantom-text-secondary mt-1 max-w-2xl">Define exactly what PHANTOM is authorized to assess. Scope rules are enforced again at scan execution and outbound request time.</p></div>
        <div className="flex items-center gap-2"><Status enabled={draft.enabled} configured={scope.configured} dirty={dirty}/><button onClick={() => void refresh()} className="h-9 px-3 border border-phantom-border rounded-lg text-xs flex items-center gap-2 hover:bg-phantom-surface"><RefreshCw size={13}/>Refresh</button><button onClick={() => void save()} disabled={saving || !dirty || validationIssues.length > 0} title={validationIssues[0] ?? (dirty ? 'Save the current scope policy' : 'No unsaved changes')} className="h-9 px-3 rounded-lg bg-phantom-text-primary text-black text-xs font-semibold flex items-center gap-2 disabled:opacity-40"><Save size={13}/>{saving ? 'Saving…' : dirty ? 'Save policy' : 'Saved'}</button></div>
      </div>
      {dirty && <div className="max-w-6xl mx-auto mt-4 rounded-lg border border-phantom-amber/25 bg-phantom-amber/5 px-3 py-2 text-xs text-phantom-amber"><strong>Unsaved policy changes.</strong> Saving a changed policy immediately cancels queued and running scans so they cannot continue under stale authorization.</div>}
      {validationIssues.length > 0 && <div className="max-w-6xl mx-auto mt-3 rounded-lg border border-phantom-coral/30 bg-phantom-coral/10 px-3 py-2 text-xs text-phantom-coral"><strong>Policy needs attention.</strong> {validationIssues[0]}</div>}
      {error && <div className="max-w-6xl mx-auto mt-3 rounded-lg border border-phantom-coral/30 bg-phantom-coral/10 px-3 py-2 text-xs text-phantom-coral">{error}</div>}
      {message && <div className="max-w-6xl mx-auto mt-4 rounded-lg border border-phantom-cyan/20 bg-phantom-cyan/5 px-3 py-2 text-xs text-phantom-cyan">{message}</div>}
    </header>

    <main className="max-w-6xl mx-auto p-6 space-y-5">
      <section className="border border-phantom-border rounded-xl bg-phantom-surface overflow-hidden">
        <div className="px-4 py-3 border-b border-phantom-border flex items-center justify-between">
          <div className="flex items-center gap-2"><ShieldCheck size={14} className="text-phantom-cyan"/><span className="text-xs font-semibold">Scope approval</span></div>
          <span className="text-[10px] uppercase tracking-wider text-phantom-text-tertiary">{scope.approval_status}</span>
        </div>
        <div className="p-4 grid lg:grid-cols-[1fr_auto] gap-4 items-end">
          <div>
            <div className="text-xs text-phantom-text-secondary leading-5">
              Authorization acknowledgement records that the configured targets are authorized. Approval is a separate governance step and is required before scan execution.
            </div>
            <div className="mt-3 text-[11px] text-phantom-text-tertiary">
              {scope.approved_by ? `Approved/rejected by ${scope.approved_by}` : 'No approval decision recorded.'}
              {scope.approval_comment ? ` · ${scope.approval_comment}` : ''}
            </div>
            <input value={approvalComment} onChange={e => setApprovalComment(e.target.value)} maxLength={2000} placeholder="Approval note (optional)" className="control mt-3 w-full"/>
          </div>
          <div className="flex gap-2">
            <button onClick={() => void changeApproval(false)} disabled={approvalBusy || !scope.configured} className="h-9 px-3 rounded-lg border border-phantom-coral/30 text-phantom-coral text-xs disabled:opacity-40">Reject</button>
            <button onClick={() => void changeApproval(true)} disabled={approvalBusy || !scope.configured || !scope.enabled || !scope.authorization_acknowledged} className="h-9 px-3 rounded-lg bg-phantom-cyan/15 border border-phantom-cyan/30 text-phantom-cyan text-xs font-semibold disabled:opacity-40">{approvalBusy ? 'Saving…' : 'Approve scope'}</button>
          </div>
        </div>
      </section>

      <section className="grid lg:grid-cols-[1.5fr_1fr] gap-5">
        <Panel title="Authorization boundary" icon={LockKeyhole}>
          <div className="rounded-lg border border-phantom-amber/25 bg-phantom-amber/5 p-3 text-xs text-phantom-text-secondary flex gap-3"><AlertTriangle size={15} className="text-phantom-amber shrink-0 mt-0.5"/><div><strong className="text-phantom-text-primary">Only add systems you are authorized to assess.</strong><div className="mt-1 leading-5">PHANTOM rejects local/private destinations and applies this workspace allowlist before a scan and before each outbound request.</div></div></div>
          <Field title="Authorized targets" hint="Hostname, wildcard subdomain, public IP, or public CIDR."><div className="flex gap-2"><input value={targetInput} onChange={e => setTargetInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && add('authorized_targets', targetInput, () => setTargetInput(''))} placeholder="example.com or *.example.com" className="control flex-1"/><button onClick={() => add('authorized_targets', targetInput, () => setTargetInput(''))} className="iconButton"><Plus size={15}/></button></div><Chips values={draft.authorized_targets} onRemove={x => remove('authorized_targets', x)} empty="No authorized targets yet."/></Field>
          <Field title="Excluded targets" hint="Exclusions override authorization, including wildcard and CIDR matches."><div className="flex gap-2"><input value={excludedInput} onChange={e => setExcludedInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && add('excluded_targets', excludedInput, () => setExcludedInput(''))} placeholder="admin.example.com" className="control flex-1"/><button onClick={() => add('excluded_targets', excludedInput, () => setExcludedInput(''))} className="iconButton"><Plus size={15}/></button></div><Chips values={draft.excluded_targets} onRemove={x => remove('excluded_targets', x)} empty="No exclusions."/></Field>
          <label className="flex items-start gap-3 rounded-lg border border-phantom-border bg-phantom-panel p-3 cursor-pointer"><input type="checkbox" checked={draft.authorization_acknowledged} onChange={e => { const checked = e.target.checked; setDraft(d => ({...d, authorization_acknowledged: checked, authorization_reconfirmed: checked ? true : false})); setError(''); setMessage(''); }} className="mt-0.5 accent-cyan-400"/><span className="text-xs leading-5"><strong className="text-phantom-text-primary">I confirm this workspace has authorization to assess the configured targets.</strong><span className="block text-phantom-text-tertiary mt-0.5">Required before the scope can be enabled.</span></span></label>
          <label className="flex items-center justify-between rounded-lg border border-phantom-border bg-phantom-panel p-3"><span><span className="text-xs font-medium">Enforce workspace scope</span><span className="block text-[11px] text-phantom-text-tertiary mt-1">When disabled, scans cannot execute.</span></span><button onClick={() => { setDraft(d => ({...d, enabled: !d.enabled})); setError(''); setMessage(''); }} className={`w-11 h-6 rounded-full p-1 transition ${draft.enabled ? 'bg-phantom-cyan/70' : 'bg-phantom-surface border border-phantom-border'}`} aria-label="Toggle scope enforcement"><span className={`block w-4 h-4 rounded-full bg-white transition-transform ${draft.enabled ? 'translate-x-5' : ''}`}/></button></label>
          {draft.enabled && !canEnable && <div className="text-[11px] text-phantom-coral">Scope cannot be enabled until authorization is acknowledged and at least one target is configured.</div>}
        </Panel>

        <Panel title="Policy limits" icon={ShieldCheck}>
          <NumberField label="Maximum requests / scan" value={draft.max_requests} min={1} max={250} onChange={v => updatePolicy(d => ({...d, max_requests: v}))}/>
          <NumberField label="Maximum concurrent scans" value={draft.max_concurrency} min={1} max={16} onChange={v => updatePolicy(d => ({...d, max_concurrency: v}))}/>
          <NumberField label="Maximum redirect hops" value={draft.max_redirects} min={0} max={5} onChange={v => updatePolicy(d => ({...d, max_redirects: v}))}/>
          <div className="mt-4 rounded-lg border border-phantom-border bg-phantom-panel p-3"><div className="text-[10px] uppercase tracking-wider text-phantom-text-tertiary">Effective server limits</div><div className="grid grid-cols-3 gap-3 mt-3"><Metric label="Requests" value={scope.effective_limits.max_requests}/><Metric label="Concurrency" value={scope.effective_limits.max_concurrency}/><Metric label="Redirects" value={scope.effective_limits.max_redirects}/></div></div>
          <p className="text-[11px] text-phantom-text-tertiary leading-5 mt-3">Workspace limits can only reduce the server safety envelope; they cannot raise it.</p>
        </Panel>
      </section>

      <section className="grid lg:grid-cols-2 gap-5">
        <Panel title="Network policy" icon={Globe2}>
          <Field title="Allowed ports" hint="Only these destination ports may be contacted."><div className="flex gap-2"><input value={portInput} onChange={e => setPortInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && addPort()} placeholder="443" inputMode="numeric" className="control flex-1"/><button onClick={addPort} className="iconButton"><Plus size={15}/></button></div><Chips values={draft.allowed_ports.map(String)} onRemove={x => updatePolicy(d => ({...d, allowed_ports: d.allowed_ports.filter(p => String(p) !== x)}))} empty="No ports configured."/></Field>
          <Field title="Allowed paths" hint="Path prefixes PHANTOM may request."><div className="flex gap-2"><input value={allowedPathInput} onChange={e => setAllowedPathInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && add('allowed_paths', allowedPathInput, () => setAllowedPathInput(''))} placeholder="/ or /api" className="control flex-1"/><button onClick={() => add('allowed_paths', allowedPathInput, () => setAllowedPathInput(''))} className="iconButton"><Plus size={15}/></button></div><Chips values={draft.allowed_paths} onRemove={x => remove('allowed_paths', x)} empty="No allowed paths."/></Field>
          <Field title="Blocked paths" hint="Blocks override allowed paths."><div className="flex gap-2"><input value={blockedPathInput} onChange={e => setBlockedPathInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && add('blocked_paths', blockedPathInput, () => setBlockedPathInput(''))} placeholder="/admin" className="control flex-1"/><button onClick={() => add('blocked_paths', blockedPathInput, () => setBlockedPathInput(''))} className="iconButton"><Plus size={15}/></button></div><Chips values={draft.blocked_paths} onRemove={x => remove('blocked_paths', x)} empty="No blocked paths."/></Field>
        </Panel>

        <Panel title="Pre-flight scope check" icon={CircleHelp}>
          <p className="text-xs text-phantom-text-secondary leading-5">Test a target against the saved policy without starting a scan. This is useful for validating ports, paths, exclusions, and authorization before execution.</p>
          <div className="flex gap-2 mt-4"><input value={checkInput} onChange={e => setCheckInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && void check()} placeholder="https://example.com" className="control flex-1"/><button onClick={() => void check()} disabled={checking || !checkInput.trim()} className="h-9 px-3 rounded-lg bg-phantom-surface border border-phantom-border text-xs font-medium disabled:opacity-40">{checking ? 'Checking…' : 'Check target'}<ChevronRight size={13} className="inline ml-1"/></button></div>
          {checkResult && <div className={`mt-4 rounded-lg border p-3 ${checkResult.allowed ? 'border-phantom-cyan/25 bg-phantom-cyan/5' : 'border-phantom-coral/25 bg-phantom-coral/5'}`}><div className="flex items-center gap-2 text-xs font-semibold">{checkResult.allowed ? <Check size={14} className="text-phantom-cyan"/> : <X size={14} className="text-phantom-coral"/>}{checkResult.allowed ? 'Target is inside the saved scope' : 'Target is outside the saved scope'}</div><div className="mt-2 text-[11px] text-phantom-text-secondary font-mono break-all">{checkResult.allowed ? `${checkResult.host ?? 'unknown'}:${checkResult.port ?? '—'}` : checkResult.reason}</div></div>}
          <div className="mt-5 rounded-lg border border-phantom-border bg-phantom-panel p-3"><div className="text-[10px] uppercase tracking-wider text-phantom-text-tertiary">Enforcement chain</div><div className="mt-3 space-y-2 text-[11px] text-phantom-text-secondary"><Step n="01" text="Create / schedule scan"/><Step n="02" text="Validate target against workspace policy"/><Step n="03" text="Re-check every outbound request"/><Step n="04" text="Re-check redirect destinations"/></div></div>
        </Panel>
      </section>
    </main>
  </div>;
}

function validateDraft(draft: Draft): string[] {
  const issues: string[] = [];
  if (draft.enabled && draft.authorized_targets.length === 0) issues.push('Add at least one authorized target before enabling the scope.');
  if (draft.enabled && !draft.authorization_acknowledged) issues.push('Re-confirm authorization after changing the policy before enabling it.');
  if (!draft.allowed_ports.length) issues.push('Configure at least one allowed destination port.');
  if (!draft.allowed_paths.length) issues.push('Configure at least one allowed path prefix.');
  if (draft.allowed_paths.some(path => !path.startsWith('/'))) issues.push('Allowed paths must start with /.');
  if (draft.blocked_paths.some(path => !path.startsWith('/'))) issues.push('Blocked paths must start with /.');
  if (!Number.isFinite(draft.max_requests) || draft.max_requests < 1 || draft.max_requests > 250) issues.push('Maximum requests must be between 1 and 250.');
  if (!Number.isFinite(draft.max_concurrency) || draft.max_concurrency < 1 || draft.max_concurrency > 16) issues.push('Maximum concurrency must be between 1 and 16.');
  if (!Number.isFinite(draft.max_redirects) || draft.max_redirects < 0 || draft.max_redirects > 5) issues.push('Maximum redirects must be between 0 and 5.');
  return issues;
}

function toDraft(value: WorkspaceScope): Draft { return { enabled: value.enabled, authorized_targets: [...value.authorized_targets], excluded_targets: [...value.excluded_targets], allowed_ports: [...value.allowed_ports], allowed_paths: [...value.allowed_paths], blocked_paths: [...value.blocked_paths], max_requests: value.max_requests, max_concurrency: value.max_concurrency, max_redirects: value.max_redirects, authorization_acknowledged: value.authorization_acknowledged, authorization_reconfirmed: false }; }
function unique(values: string[]) { return [...new Set(values)]; }
function uniqueNumbers(values: number[]) { return [...new Set(values)]; }
function errorText(error: unknown, fallback: string) { if (error instanceof Error) return error.message; return fallback; }
function Panel({title, icon: Icon, children}:{title:string;icon:React.ComponentType<{size?:number;className?:string}>;children:React.ReactNode}) { return <section className="border border-phantom-border rounded-xl bg-phantom-surface overflow-hidden"><div className="px-4 py-3 border-b border-phantom-border flex items-center gap-2"><Icon size={14} className="text-phantom-cyan"/><span className="text-xs font-semibold">{title}</span></div><div className="p-4 space-y-4">{children}</div></section>; }
function Field({title,hint,children}:{title:string;hint:string;children:React.ReactNode}) { return <div><div className="mb-2"><div className="text-xs font-medium">{title}</div><div className="text-[10px] text-phantom-text-tertiary mt-0.5">{hint}</div></div>{children}</div>; }
function Chips({values,onRemove,empty}:{values:string[];onRemove:(value:string)=>void;empty:string}) { return <div className="flex flex-wrap gap-1.5 mt-2">{values.length ? values.map(value => <span key={value} className="inline-flex items-center gap-1 rounded-md border border-phantom-border bg-phantom-panel px-2 py-1 text-[10px] font-mono text-phantom-text-secondary">{value}<button onClick={() => onRemove(value)} className="text-phantom-text-tertiary hover:text-phantom-coral" aria-label={`Remove ${value}`}><X size={11}/></button></span>) : <span className="text-[10px] text-phantom-text-tertiary">{empty}</span>}</div>; }
function NumberField({label,value,min,max,onChange}:{label:string;value:number;min:number;max:number;onChange:(value:number)=>void}) { return <label className="block"><span className="text-xs font-medium">{label}</span><input type="number" min={min} max={max} value={value} onChange={e => onChange(Number(e.target.value))} className="control mt-2 w-full"/></label>; }
function Metric({label,value}:{label:string;value:number}) { return <div><div className="text-[10px] text-phantom-text-tertiary">{label}</div><div className="text-sm font-mono mt-1">{value}</div></div>; }
function Status({enabled,configured,dirty}:{enabled:boolean;configured:boolean;dirty:boolean}) { return <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] uppercase tracking-wider ${enabled ? 'border-phantom-cyan/25 bg-phantom-cyan/5 text-phantom-cyan' : 'border-phantom-border bg-phantom-panel text-phantom-text-tertiary'}`}><span className={`w-1.5 h-1.5 rounded-full ${enabled ? 'bg-phantom-cyan' : 'bg-phantom-text-tertiary'}`}/>{dirty ? 'Unsaved changes' : enabled ? 'Enforced' : configured ? 'Configured / disabled' : 'Not configured'}</span>; }
function Step({n,text}:{n:string;text:string}) { return <div className="flex items-center gap-2"><span className="font-mono text-phantom-text-tertiary">{n}</span><span>{text}</span></div>; }
