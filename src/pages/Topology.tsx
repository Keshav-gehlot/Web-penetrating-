import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle, Box, ChevronDown, CircleDot, Database, Globe2, Minus, Network,
  Plus, RefreshCw, Search, Server, ShieldAlert, Target, Waypoints, X, ZoomIn, ZoomOut,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { authHeaders } from '../lib/auth';
import { cn } from '../lib/utils';

const API = (import.meta.env.VITE_PHANTOM_API_URL ?? 'http://localhost:8000').replace(/\/$/, '');

type TopologyNode = {
  id: string;
  type: 'internet' | 'asset' | 'dns' | 'service' | 'technology' | 'endpoint' | 'finding';
  label: string;
  subtitle?: string;
  asset_id?: string;
  finding_id_ref?: string;
  service_id_ref?: string;
  port?: number;
  protocol?: string;
  service?: string | null;
  risk?: string;
  severity?: string;
  status?: string;
  finding_count?: number;
  addresses?: string[];
  delta?: 'new' | 'persistent';
  [key: string]: unknown;
};

type TopologyEdge = {
  id: string;
  source: string;
  target: string;
  relation: string;
  label?: string;
  delta?: string;
};

type TopologyData = {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  meta: {
    scan_id: string | null;
    previous_scan_id: string | null;
    delta: boolean;
    node_count: number;
    edge_count: number;
    available_scans: Array<{
      id: string;
      asset_id: string | null;
      host: string;
      profile: string;
      status: string;
      created_at: string | null;
      completed_at: string | null;
    }>;
  };
};

const TYPE_OPTIONS = ['all', 'asset', 'service', 'endpoint', 'technology', 'dns', 'finding'];
const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low', 'info'];
const TYPE_X: Record<string, number> = {
  internet: 100, dns: 280, asset: 500, technology: 760, service: 760, endpoint: 760, finding: 1050,
};

function riskClass(value?: string) {
  return value === 'critical' ? 'text-phantom-coral border-phantom-coral/40 bg-phantom-coral/10'
    : value === 'high' ? 'text-orange-300 border-orange-400/30 bg-orange-400/10'
    : value === 'medium' ? 'text-yellow-300 border-yellow-400/30 bg-yellow-400/10'
    : 'text-phantom-text-tertiary border-phantom-border bg-phantom-panel';
}

function NodeIcon({ type }: { type: TopologyNode['type'] }) {
  if (type === 'internet') return <Globe2 size={18} />;
  if (type === 'asset') return <Server size={18} />;
  if (type === 'service') return <Waypoints size={18} />;
  if (type === 'endpoint') return <Target size={18} />;
  if (type === 'finding') return <ShieldAlert size={18} />;
  if (type === 'technology') return <Box size={18} />;
  return <Network size={18} />;
}

function formatTime(value?: string | null) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function Topology() {
  const navigate = useNavigate();
  const [data, setData] = useState<TopologyData | null>(null);
  const [query, setQuery] = useState('');
  const [nodeType, setNodeType] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [scanId, setScanId] = useState('');
  const [delta, setDelta] = useState(false);
  const [selected, setSelected] = useState<TopologyNode | null>(null);
  const [zoom, setZoom] = useState(1);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    setError('');
    try {
      const params = new URLSearchParams();
      if (query.trim()) params.set('q', query.trim());
      if (nodeType !== 'all') params.set('node_type', nodeType);
      if (severity !== 'all') params.set('severity', severity);
      if (scanId) params.set('scan_id', scanId);
      if (delta) params.set('delta', 'true');
      const response = await fetch(`${API}/api/v1/topology?${params.toString()}`, { headers: authHeaders() });
      if (!response.ok) throw new Error(await response.text());
      const value = await response.json() as TopologyData;
      setData(value);
      if (selected) setSelected(value.nodes.find(node => node.id === selected.id) ?? null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to load topology');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(); }, [query, nodeType, severity, scanId, delta]);

  const visibleNodes = data?.nodes ?? [];
  const nodeMap = useMemo(() => new Map(visibleNodes.map(node => [node.id, node])), [visibleNodes]);
  const positions = useMemo<Map<string, { x: number; y: number }>>(() => {
    const counts: Record<string, number> = {};
    const result = new Map<string, { x: number; y: number }>();
    for (const node of visibleNodes) {
      const index = counts[node.type] ?? 0;
      counts[node.type] = index + 1;
      result.set(node.id, { x: TYPE_X[node.type] ?? 760, y: 110 + index * 92 });
    }
    return result;
  }, [visibleNodes]);

  const graphHeight = Math.max(720, ...Array.from(positions.values()).map(position => position.y + 90));
  const selectedFindings = useMemo(() => {
    if (!selected) return [];
    if (selected.type === 'finding') return [selected];
    const findingIds = new Set(
      (data?.edges ?? [])
        .filter(edge => edge.source === selected.id && edge.relation === 'has-finding')
        .map(edge => edge.target),
    );
    return visibleNodes.filter(node => findingIds.has(node.id));
  }, [data, selected, visibleNodes]);

  function openNode(node: TopologyNode) {
    setSelected(node);
    if (node.type === 'finding' && node.finding_id_ref) {
      navigate(`/investigation?finding=${encodeURIComponent(node.finding_id_ref)}`);
    }
    if (node.type === 'asset' && node.asset_id) {
      navigate(`/assets?asset=${encodeURIComponent(node.asset_id)}`);
    }
  }

  return (
    <div className="flex flex-col h-full bg-phantom-bg">
      <header className="flex-none px-5 py-4 border-b border-phantom-border bg-phantom-surface/70">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-phantom-cyan mb-1">Attack surface graph</div>
            <h1 className="text-lg font-semibold tracking-tight">Data-driven topology</h1>
            <p className="text-xs text-phantom-text-secondary mt-1">
              Assets, DNS, services, endpoints, technologies and findings observed by PHANTOM scans.
            </p>
          </div>
          <button onClick={() => void load()} className="h-8 px-3 rounded-lg border border-phantom-border text-[11px] flex items-center gap-2 hover:border-phantom-cyan/50">
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''}/> Refresh
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2 mt-4">
          <div className="relative min-w-[220px] flex-1 max-w-sm">
            <Search size={13} className="absolute left-3 top-2.5 text-phantom-text-tertiary"/>
            <input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search nodes..." className="w-full h-8 pl-8 pr-3 rounded-lg border border-phantom-border bg-phantom-panel text-xs outline-none focus:border-phantom-cyan/50"/>
          </div>
          <Select value={nodeType} onChange={setNodeType} options={TYPE_OPTIONS} label="Type"/>
          <Select value={severity} onChange={setSeverity} options={SEVERITY_OPTIONS} label="Risk"/>
          <Select
            value={scanId}
            onChange={setScanId}
            options={['', ...(data?.meta.available_scans ?? []).map(scan => scan.id)]}
            labels={['Latest graph', ...(data?.meta.available_scans ?? []).map(scan => `${scan.host} · ${scan.profile}`)]}
            label="Scan"
          />
          <button onClick={() => setDelta(value => !value)} className={cn('h-8 px-3 rounded-lg border text-[11px] font-medium', delta ? 'border-phantom-cyan/60 text-phantom-cyan bg-phantom-cyan/5' : 'border-phantom-border text-phantom-text-secondary')}>
            Timeline / Delta
          </button>
          <div className="ml-auto flex items-center gap-1 border border-phantom-border rounded-lg bg-phantom-panel">
            <button onClick={() => setZoom(value => Math.max(.55, +(value - .1).toFixed(2)))} className="p-2 hover:text-phantom-cyan" title="Zoom out"><ZoomOut size={13}/></button>
            <span className="text-[10px] font-mono w-10 text-center">{Math.round(zoom * 100)}%</span>
            <button onClick={() => setZoom(value => Math.min(1.8, +(value + .1).toFixed(2)))} className="p-2 hover:text-phantom-cyan" title="Zoom in"><ZoomIn size={13}/></button>
            <button onClick={() => setZoom(1)} className="p-2 hover:text-phantom-cyan" title="Reset zoom"><CircleDot size={13}/></button>
          </div>
        </div>
      </header>

      <div className="flex-1 flex min-h-0 overflow-hidden">
        <main className="flex-1 min-w-0 overflow-auto relative bg-[radial-gradient(circle_at_center,rgba(75,85,99,0.12)_1px,transparent_1px)] [background-size:24px_24px]">
          {error && <div className="absolute z-20 top-4 left-4 right-4 p-3 rounded-lg border border-phantom-coral/30 bg-phantom-coral/10 text-xs text-phantom-coral">{error}</div>}
          {!visibleNodes.length && !loading && (
            <div className="h-full flex items-center justify-center text-sm text-phantom-text-tertiary">No topology observations match the current filters.</div>
          )}
          <svg width={1450 * zoom} height={graphHeight * zoom} viewBox={`0 0 1450 ${graphHeight}`} className="min-w-full min-h-full">
            <defs>
              <marker id="topology-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
                <path d="M0,0 L0,6 L7,3 z" fill="currentColor"/>
              </marker>
            </defs>
            <g>
              {(data?.edges ?? []).map(edge => {
                const source = positions.get(edge.source);
                const target = positions.get(edge.target);
                if (!source || !target || !nodeMap.has(edge.source) || !nodeMap.has(edge.target)) return null;
                const changed = edge.delta === 'new';
                return (
                  <g key={edge.id} className={changed ? 'text-phantom-cyan' : 'text-phantom-border-strong'}>
                    <line x1={source.x + 70} y1={source.y + 22} x2={target.x - 70} y2={target.y + 22} stroke="currentColor" strokeWidth={changed ? 2 : 1.25} markerEnd="url(#topology-arrow)" opacity={changed ? .95 : .55}/>
                    <text x={(source.x + target.x) / 2} y={(source.y + target.y) / 2 - 5} textAnchor="middle" className="fill-phantom-text-tertiary text-[9px]">{edge.label ?? edge.relation}</text>
                  </g>
                );
              })}
              {visibleNodes.map(node => {
                const position = positions.get(node.id)!;
                const highlighted = selected?.id === node.id;
                return (
                  <g key={node.id} transform={`translate(${position.x - 70} ${position.y})`} onClick={() => openNode(node)} className="cursor-pointer">
                    <rect width="140" height="68" rx="12" className={cn(
                      'fill-phantom-surface stroke-phantom-border',
                      highlighted && 'stroke-phantom-cyan',
                      node.risk && ['critical', 'high'].includes(node.risk) && 'stroke-phantom-coral/70',
                      node.delta === 'new' && 'stroke-phantom-cyan',
                    )} strokeWidth={highlighted ? 2 : 1}/>
                    <foreignObject x="10" y="9" width="120" height="50">
                      <div className="w-full h-full text-left pointer-events-none">
                        <div className="flex items-center gap-2">
                          <span className={cn('p-1.5 rounded-lg border', riskClass(node.risk))}><NodeIcon type={node.type}/></span>
                          <span className="text-[10px] uppercase tracking-wider text-phantom-text-tertiary truncate">{node.type}</span>
                          {node.delta === 'new' && <span className="text-[8px] font-mono text-phantom-cyan">NEW</span>}
                        </div>
                        <div className="text-[11px] font-semibold truncate mt-1">{node.label}</div>
                        <div className="text-[8px] text-phantom-text-tertiary truncate">{node.subtitle ?? node.status ?? ''}</div>
                      </div>
                    </foreignObject>
                  </g>
                );
              })}
            </g>
          </svg>
        </main>

        <aside className="w-[320px] flex-none border-l border-phantom-border bg-phantom-surface/40 overflow-y-auto">
          {selected ? (
            <div className="p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-[9px] uppercase tracking-[0.16em] text-phantom-cyan">{selected.type}</div>
                  <h2 className="text-sm font-semibold mt-1 break-words">{selected.label}</h2>
                </div>
                <button onClick={() => setSelected(null)} className="p-1.5 hover:bg-phantom-panel rounded"><X size={14}/></button>
              </div>
              <div className="mt-4 grid grid-cols-2 gap-2">
                <Metric label="Risk" value={selected.risk ?? 'info'}/>
                <Metric label="Findings" value={String(selected.finding_count ?? selectedFindings.length)}/>
                {selected.port != null && <Metric label="Port" value={`${selected.port}/${selected.protocol ?? 'tcp'}`}/>}
                {selected.state && <Metric label="State" value={selected.state}/>}
              </div>
              {selected.addresses?.length ? <Panel title="Observed addresses">{selected.addresses.map(address => <div key={address} className="font-mono text-[10px] py-1">{address}</div>)}</Panel> : null}
              {selected.type === 'asset' && selected.asset_id && <button onClick={() => navigate(`/assets?asset=${encodeURIComponent(selected.asset_id!)}`)} className="w-full h-8 rounded-lg border border-phantom-border text-[10px] hover:border-phantom-cyan/50">Open asset</button>}
              {selected.type === 'finding' && selected.finding_id_ref && <button onClick={() => navigate(`/investigation?finding=${encodeURIComponent(selected.finding_id_ref!)}`)} className="w-full h-8 rounded-lg border border-phantom-cyan/40 text-phantom-cyan text-[10px]">Open investigation</button>}
              {selected.type === 'service' && (
                <Panel title="Service findings">
                  {selectedFindings.length ? selectedFindings.map(finding => (
                    <button key={finding.id} onClick={() => finding.finding_id_ref && navigate(`/investigation?finding=${encodeURIComponent(finding.finding_id_ref)}`)} className="w-full text-left p-2 mb-2 rounded border border-phantom-border hover:border-phantom-cyan/40">
                      <div className="text-[10px] font-medium truncate">{finding.label}</div>
                      <div className="text-[9px] text-phantom-text-tertiary mt-1">{finding.risk} · {finding.status}</div>
                    </button>
                  )) : <div className="text-[10px] text-phantom-text-tertiary">No findings directly correlated to this service.</div>}
                </Panel>
              )}
              {selected.type === 'finding' && <Panel title="Finding state"><div className="text-[10px] text-phantom-text-secondary">Status: {selected.status ?? 'open'}</div><div className="text-[10px] text-phantom-text-secondary mt-1">Fingerprint: <span className="font-mono">{String(selected.fingerprint ?? '—').slice(0, 16)}</span></div></Panel>}
              <Panel title="Graph identity"><div className="text-[9px] font-mono break-all text-phantom-text-tertiary">{selected.id}</div></Panel>
            </div>
          ) : (
            <div className="p-5">
              <div className="flex items-center gap-2 text-sm font-semibold"><Network size={15}/>Topology inspector</div>
              <p className="text-[10px] text-phantom-text-tertiary mt-2">Select an asset, service, endpoint, technology or finding to inspect its relationships.</p>
              <div className="mt-5 space-y-2">
                <Legend type="asset" label="Asset / host"/>
                <Legend type="service" label="Observed service / port"/>
                <Legend type="endpoint" label="Observed endpoint"/>
                <Legend type="technology" label="Observed technology"/>
                <Legend type="finding" label="Finding overlay"/>
                <Legend type="dns" label="DNS / resolved address"/>
              </div>
              {data?.meta.scan_id && <div className="mt-5 p-3 rounded-lg border border-phantom-border bg-phantom-panel text-[10px]"><div className="font-medium">Timeline mode</div><div className="text-phantom-text-tertiary mt-1">Selected scan compared with its previous completed scan.</div><div className="font-mono mt-2 break-all">{data.meta.scan_id}</div></div>}
            </div>
          )}
        </aside>
      </div>
      <footer className="flex-none h-8 px-4 border-t border-phantom-border bg-phantom-surface/50 flex items-center justify-between text-[9px] font-mono text-phantom-text-tertiary">
        <span>{data?.meta.node_count ?? 0} nodes · {data?.meta.edge_count ?? 0} edges</span>
        <span>{delta ? 'DELTA VIEW' : 'LIVE INVENTORY'} · {data?.meta.previous_scan_id ? `BASE ${data.meta.previous_scan_id.slice(0, 8)}` : 'NO BASE SCAN'}</span>
      </footer>
    </div>
  );
}

function Select({ value, onChange, options, labels, label }: { value: string; onChange: (value: string) => void; options: string[]; labels?: string[]; label: string }) {
  return <label className="relative h-8 border border-phantom-border rounded-lg bg-phantom-panel text-[10px]">
    <span className="sr-only">{label}</span>
    <select value={value} onChange={event => onChange(event.target.value)} className="h-full pl-2 pr-7 bg-transparent outline-none appearance-none max-w-[150px]">
      {options.map((option, index) => <option key={option} value={option}>{labels?.[index] ?? (option === 'all' ? label : option)}</option>)}
    </select>
    <ChevronDown size={12} className="absolute right-2 top-2.5 pointer-events-none text-phantom-text-tertiary"/>
  </label>;
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="p-2 rounded-lg border border-phantom-border bg-phantom-panel"><div className="text-[8px] uppercase tracking-wider text-phantom-text-tertiary">{label}</div><div className="text-[10px] font-mono mt-1 truncate">{value}</div></div>;
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="mt-5"><div className="text-[9px] uppercase tracking-wider text-phantom-text-tertiary mb-2">{title}</div>{children}</section>;
}

function Legend({ type, label }: { type: TopologyNode['type']; label: string }) {
  return <div className="flex items-center gap-2 text-[10px] text-phantom-text-secondary"><span className="p-1 rounded border border-phantom-border"><NodeIcon type={type}/></span>{label}</div>;
}
