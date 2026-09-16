import React, { useMemo, useState } from 'react';
import { ExternalLink, Search, ShieldCheck, Globe2, Server, Code2, Mail, Radar } from 'lucide-react';

const SOURCES = [
  ['Shodan', 'shodan.io', 'Internet-exposed services and host intelligence', 'Server'],
  ['Google', 'google.com', 'Public web search and indexed documentation', 'Search'],
  ['WiGLE', 'wigle.net', 'Publicly contributed wireless network observations', 'Wireless'],
  ['grep.app', 'grep.app', 'Search public code indexed by the service', 'Code'],
  ['BinaryEdge', 'binaryedge.io', 'Internet measurement and threat-intelligence data', 'Threat Intel'],
  ['Onyphe', 'onyphe.io', 'Cyber threat intelligence and infrastructure data', 'Server'],
  ['GreyNoise', 'viz.greynoise.io', 'Internet scanner and noise intelligence', 'Threat Intel'],
  ['Censys', 'censys.io', 'Internet host, service and certificate data', 'Server'],
  ['Hunter', 'hunter.io', 'Business email discovery and verification', 'Email'],
  ['FOFA', 'fofa.info', 'Internet asset and service search', 'Threat Intel'],
  ['ZoomEye', 'zoomeye.org', 'Internet asset search and threat intelligence', 'Threat Intel'],
  ['LeakIX', 'leakix.net', 'Public exposure and service intelligence', 'Threat Intel'],
  ['IntelX', 'intelx.io', 'OSINT and indexed intelligence search', 'OSINT'],
  ['Netlas', 'app.netlas.io', 'Internet asset and attack-surface intelligence', 'Attack Surface'],
  ['Searchcode', 'searchcode.com', 'Public source-code search', 'Code'],
  ['urlscan.io', 'urlscan.io', 'Public web scanning and page telemetry', 'Threat Intel'],
  ['PublicWWW', 'publicwww.com', 'Public web-source and technology search', 'Code'],
  ['FullHunt', 'fullhunt.io', 'Attack-surface discovery and exposure intelligence', 'Attack Surface'],
  ['SOCRadar', 'socradar.io', 'Cyber threat intelligence and exposure data', 'Threat Intel'],
  ['IVRE', 'ivre.rocks', 'Open network-intelligence and scan-data tooling', 'Server'],
  ['crt.sh', 'crt.sh', 'Certificate transparency search', 'Certificates'],
  ['Vulners', 'vulners.com', 'Vulnerability and software intelligence', 'Vulnerabilities'],
  ['Pulsedive', 'pulsedive.com', 'Threat intelligence and indicator context', 'Threat Intel'],
  ['SecurityTrails', 'securitytrails.com', 'DNS and infrastructure intelligence', 'DNS'],
];

const CATEGORY_ICONS: Record<string, React.ComponentType<{ size?: number }>> = {
  Server, Search, Wireless: Radar, Code: Code2, 'Threat Intel': ShieldCheck, OSINT: Globe2,
  'Attack Surface': Radar, Email: Mail, Certificates: ShieldCheck, Vulnerabilities: ShieldCheck, DNS: Globe2,
};

export default function OSINT() {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('All');
  const categories = ['All', ...Array.from(new Set(SOURCES.map((s) => s[3])))];
  const filtered = useMemo(() => SOURCES.filter(([name, domain, desc, cat]) =>
    (category === 'All' || cat === category) && `${name} ${domain} ${desc}`.toLowerCase().includes(query.toLowerCase())
  ), [query, category]);

  return (
    <div className="min-h-full bg-phantom-bg p-6 lg:p-8">
      <div className="max-w-7xl mx-auto">
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-5 mb-7">
          <div>
            <div className="flex items-center gap-2 text-xs text-phantom-cyan font-mono uppercase tracking-widest mb-2"><Radar size={14}/> Public intelligence</div>
            <h1 className="text-2xl font-semibold tracking-tight">OSINT Sources</h1>
            <p className="text-sm text-phantom-text-secondary mt-2 max-w-2xl">A PHANTOM directory of public intelligence sources. Use these services only for assets and information you are authorized to research.</p>
          </div>
          <div className="text-xs text-phantom-text-tertiary font-mono">{filtered.length} / {SOURCES.length} sources</div>
        </div>

        <div className="flex flex-col md:flex-row gap-3 mb-6">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-phantom-text-tertiary" />
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search sources, categories, capabilities..." className="w-full h-10 pl-9 pr-3 rounded-lg border border-phantom-border bg-phantom-surface text-sm outline-none focus:border-phantom-cyan" />
          </div>
          <select value={category} onChange={(e) => setCategory(e.target.value)} className="h-10 px-3 rounded-lg border border-phantom-border bg-phantom-surface text-sm text-phantom-text-primary outline-none">
            {categories.map((c) => <option key={c}>{c}</option>)}
          </select>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {filtered.map(([name, domain, description, cat]) => {
            const Icon = CATEGORY_ICONS[cat] ?? Globe2;
            return (
              <a key={domain} href={`https://${domain}`} target="_blank" rel="noreferrer" className="group border border-phantom-border bg-phantom-surface rounded-xl p-4 hover:border-phantom-border-strong hover:bg-phantom-panel-hover transition-colors">
                <div className="flex items-start gap-3">
                  <div className="w-9 h-9 rounded-lg border border-phantom-border bg-phantom-bg flex items-center justify-center text-phantom-text-secondary group-hover:text-phantom-cyan"><Icon size={17}/></div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2"><h3 className="font-medium text-sm">{name}</h3><ExternalLink size={13} className="text-phantom-text-tertiary"/></div>
                    <div className="font-mono text-[11px] text-phantom-text-tertiary mt-0.5">{domain}</div>
                    <p className="text-xs text-phantom-text-secondary mt-3 leading-relaxed">{description}</p>
                    <span className="inline-flex mt-3 px-2 py-1 rounded border border-phantom-border text-[10px] uppercase tracking-wider text-phantom-text-tertiary">{cat}</span>
                  </div>
                </div>
              </a>
            );
          })}
        </div>
      </div>
    </div>
  );
}
