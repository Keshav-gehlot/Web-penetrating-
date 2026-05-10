import React from 'react';
import { Search, Filter, AlertTriangle, ArrowRight } from 'lucide-react';
import { cn } from '../lib/utils';

const vulns = [
  { id: 'VULN-9021', cve: 'CVE-2023-38545', title: 'curl heap-based buffer overflow', severity: 'critical', status: 'open', age: '2d', asset: 'api.internal.corp' },
  { id: 'VULN-9020', cve: 'CVE-2023-44487', title: 'HTTP/2 Rapid Reset Attack', severity: 'critical', status: ' investigating', age: '5d', asset: 'auth.prod.gateway' },
  { id: 'VULN-8942', cve: 'CVE-2021-44228', title: 'Log4Shell in legacy auth', severity: 'high', status: 'open', age: '14d', asset: 'legacy-db-01' },
  { id: 'VULN-8810', cve: 'N/A', title: 'Exposed Management Interface', severity: 'high', status: 'remediation', age: '21d', asset: 'k8s-worker-01' },
  { id: 'VULN-8755', cve: 'CVE-2022-26809', title: 'RPC Endpoint Mapper bypass', severity: 'medium', status: 'open', age: '30d', asset: 'cdn.global.assets' },
  { id: 'VULN-8712', cve: 'N/A', title: 'Missing Security Headers', severity: 'low', status: 'ignored', age: '45d', asset: 'api.internal.corp' },
];

export default function Vulnerabilities() {
  return (
    <div className="flex flex-col h-full bg-phantom-bg">
      <div className="flex-none p-6 border-b border-phantom-border bg-phantom-surface/50 backdrop-blur-xl z-10 sticky top-0">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-xl font-semibold tracking-tight">Vulnerability Findings</h1>
          <div className="flex gap-2">
            <button className="px-3 py-1.5 bg-phantom-panel border border-phantom-border rounded-md text-sm hover:text-phantom-text-primary transition-colors hover:bg-phantom-panel-hover">Export CSV</button>
            <button className="px-3 py-1.5 bg-phantom-cyan text-phantom-bg rounded-md text-sm font-medium hover:opacity-90 transition-opacity">Create Report</button>
          </div>
        </div>
        
        <div className="flex items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-phantom-text-tertiary" size={16} />
            <input 
              type="text" 
              placeholder="Search CVE, title, or asset..." 
              className="w-full bg-phantom-panel border border-phantom-border rounded-lg pl-9 pr-4 py-2 text-sm focus:outline-none focus:border-phantom-text-secondary transition-colors"
            />
          </div>
          <button className="flex items-center gap-2 px-3 py-2 bg-phantom-panel border border-phantom-border rounded-lg text-sm text-phantom-text-secondary hover:text-phantom-text-primary transition-colors">
            <Filter size={14} />
            Severity: Critical, High
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="border border-phantom-border rounded-xl bg-phantom-surface overflow-hidden">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-phantom-border bg-phantom-panel/50">
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider w-10"></th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">ID / CVE</th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Title / Asset</th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Severity</th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Status</th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Age</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="text-sm">
              {vulns.map((vuln) => (
                <tr key={vuln.id} className="border-b border-phantom-border last:border-0 table-row-hover transition-colors cursor-pointer group">
                  <td className="px-4 py-3 pl-6">
                    <input type="checkbox" className="rounded border-phantom-border bg-phantom-panel w-4 h-4 accent-phantom-cyan cursor-pointer" />
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-mono text-xs text-phantom-text-primary">{vuln.id}</div>
                    <div className="font-mono text-[10px] text-phantom-text-tertiary mt-0.5">{vuln.cve}</div>
                  </td>
                  <td className="px-4 py-3">
                     <div className="font-medium text-phantom-text-primary mb-1">{vuln.title}</div>
                     <div className="text-xs text-phantom-text-secondary font-mono">{vuln.asset}</div>
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={vuln.severity} />
                  </td>
                  <td className="px-4 py-3">
                    <span className="capitalize text-xs text-phantom-text-secondary">{vuln.status}</span>
                  </td>
                  <td className="px-4 py-3 text-phantom-text-tertiary text-xs">{vuln.age}</td>
                  <td className="px-4 py-3 text-right">
                    <button className="text-phantom-text-tertiary hover:text-phantom-text-primary p-2 opacity-0 group-hover:opacity-100 transition-all rounded-md hover:bg-phantom-panel">
                      <ArrowRight size={16} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const isCritical = severity === 'critical';
  const isHigh = severity === 'high';
  
  return (
    <div className="flex items-center gap-2">
      <div className={cn(
        "w-2 h-2 rounded-full",
        isCritical && "bg-phantom-coral animate-pulse",
        isHigh && "bg-phantom-amber",
        severity === 'medium' && "bg-phantom-cyan",
        severity === 'low' && "bg-phantom-text-tertiary"
      )} />
      <span className={cn(
        "text-xs font-medium capitalize",
        isCritical ? "text-phantom-coral" : "text-phantom-text-secondary"
      )}>
        {severity}
      </span>
    </div>
  );
}
