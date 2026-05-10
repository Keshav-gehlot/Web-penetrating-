import React from 'react';
import { Search, Filter, Plus, MoreHorizontal, ShieldCheck, ShieldAlert } from 'lucide-react';

const assets = [
  { id: '1', hostname: 'api.internal.corp', ip: '10.0.12.45', type: 'Server', risk: 'high', lastScan: '2h ago' },
  { id: '2', hostname: 'auth.prod.gateway', ip: '192.168.1.100', type: 'Gateway', risk: 'low', lastScan: '1d ago' },
  { id: '3', hostname: 'legacy-db-01', ip: '10.0.15.22', type: 'Database', risk: 'critical', lastScan: '4h ago' },
  { id: '4', hostname: 'cdn.global.assets', ip: '172.16.0.5', type: 'CDN Node', risk: 'medium', lastScan: '5h ago' },
  { id: '5', hostname: 'k8s-worker-01', ip: '10.0.50.11', type: 'Container', risk: 'low', lastScan: '12h ago' },
];

export default function AssetManagement() {
  return (
    <div className="flex flex-col h-full bg-phantom-bg">
      <div className="flex-none p-6 border-b border-phantom-border bg-phantom-surface/50 backdrop-blur-xl z-10 sticky top-0">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-xl font-semibold tracking-tight">Asset Inventory</h1>
          <button className="flex items-center gap-2 px-3 py-1.5 bg-phantom-text-primary text-black rounded-md text-sm font-medium hover:opacity-90 transition-opacity">
            <Plus size={14} />
            Add Asset
          </button>
        </div>
        
        <div className="flex items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-phantom-text-tertiary" size={16} />
            <input 
              type="text" 
              placeholder="Search by hostname, IP, or type..." 
              className="w-full bg-phantom-panel border border-phantom-border rounded-lg pl-9 pr-4 py-2 text-sm focus:outline-none focus:border-phantom-text-secondary transition-colors"
            />
          </div>
          <button className="flex items-center gap-2 px-3 py-2 bg-phantom-panel border border-phantom-border rounded-lg text-sm text-phantom-text-secondary hover:text-phantom-text-primary transition-colors">
            <Filter size={14} />
            Filters
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="border border-phantom-border rounded-xl bg-phantom-surface overflow-hidden">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-phantom-border bg-phantom-panel/50">
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider w-10"></th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Hostname</th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">IP Address</th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Type</th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Risk Profile</th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Last Scan</th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider text-right"></th>
              </tr>
            </thead>
            <tbody className="text-sm">
              {assets.map((asset) => (
                <tr key={asset.id} className="border-b border-phantom-border last:border-0 table-row-hover transition-colors cursor-pointer group">
                  <td className="px-4 py-3 pl-6">
                    <input type="checkbox" className="rounded border-phantom-border bg-phantom-panel w-4 h-4 accent-phantom-cyan cursor-pointer" />
                  </td>
                  <td className="px-4 py-3 font-medium text-phantom-text-primary flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-phantom-cyan/50 group-hover:bg-phantom-cyan transition-colors" />
                    {asset.hostname}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-phantom-text-secondary">{asset.ip}</td>
                  <td className="px-4 py-3 text-phantom-text-secondary">{asset.type}</td>
                  <td className="px-4 py-3">
                    <RiskBadge risk={asset.risk} />
                  </td>
                  <td className="px-4 py-3 text-phantom-text-tertiary text-xs">{asset.lastScan}</td>
                  <td className="px-4 py-3 text-right">
                    <button className="text-phantom-text-tertiary hover:text-phantom-text-primary p-1 opacity-0 group-hover:opacity-100 transition-all">
                      <MoreHorizontal size={16} />
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

function RiskBadge({ risk }: { risk: string }) {
  const styles: Record<string, string> = {
    critical: 'text-phantom-coral bg-phantom-coral/10 border-phantom-coral/20',
    high: 'text-phantom-amber bg-phantom-amber/10 border-phantom-amber/20',
    medium: 'text-phantom-cyan bg-phantom-cyan/10 border-phantom-cyan/20',
    low: 'text-phantom-text-secondary bg-phantom-panel border-phantom-border',
  };
  
  const icon = risk === 'critical' || risk === 'high' ? ShieldAlert : ShieldCheck;
  const Icon = icon;

  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium border ${styles[risk] || styles.low}`}>
      <Icon size={12} />
      <span className="capitalize">{risk}</span>
    </span>
  );
}
