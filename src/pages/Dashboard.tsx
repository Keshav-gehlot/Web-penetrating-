import React from 'react';
import { motion } from 'motion/react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { Shield, AlertTriangle, Zap, Server, ArrowUpRight, ArrowDownRight, Clock, CheckCircle } from 'lucide-react';
import { cn } from '../lib/utils';

const scanData = [
  { time: '00:00', value: 12 }, { time: '04:00', value: 18 },
  { time: '08:00', value: 45 }, { time: '12:00', value: 30 },
  { time: '16:00', value: 55 }, { time: '20:00', value: 25 },
  { time: '24:00', value: 20 },
];

const vulnData = [
  { name: 'Critical', value: 12, color: 'var(--color-phantom-coral)' },
  { name: 'High', value: 45, color: 'var(--color-phantom-amber)' },
  { name: 'Medium', value: 128, color: 'var(--color-phantom-cyan)' },
  { name: 'Low', value: 312, color: 'var(--color-phantom-text-tertiary)' },
];

export default function Dashboard() {
  return (
    <div className="flex flex-col min-h-full p-8 max-w-7xl mx-auto w-full gap-8">
      {/* Header */}
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-phantom-text-primary tracking-tight">Overview</h1>
          <p className="text-sm text-phantom-text-tertiary mt-1">Real-time infrastructure security posture.</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-phantom-surface border border-phantom-border rounded-md text-xs font-mono text-phantom-text-secondary">
            <span className="w-1.5 h-1.5 rounded-full bg-phantom-cyan animate-pulse"></span>
            Last updated: Just now
          </div>
          <button className="flex items-center gap-2 px-4 py-1.5 bg-phantom-text-primary text-black rounded-md text-sm font-medium hover:opacity-90 transition-opacity">
            <Zap size={14} />
            <span>Launch Scan</span>
          </button>
        </div>
      </header>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard title="Risk Score" value="78/100" trend="+2.4" icon={Shield} color="text-phantom-cyan" />
        <MetricCard title="Critical Exposures" value="12" trend="-3" icon={AlertTriangle} color="text-phantom-coral" trendDownIsGood />
        <MetricCard title="Active Scans" value="4" trend="+1" icon={Zap} color="text-phantom-text-primary" />
        <MetricCard title="Assets Monitored" value="1,204" trend="+12" icon={Server} color="text-phantom-text-primary" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Chart */}
        <div className="lg:col-span-2 bg-phantom-surface border border-phantom-border rounded-xl p-5 flex flex-col shadow-sm">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-sm font-semibold text-phantom-text-secondary">Scan Volume & Threat Detections</h2>
            <div className="flex gap-2">
              <span className="px-2 py-1 rounded bg-phantom-panel text-xs text-phantom-text-primary">24h</span>
              <span className="px-2 py-1 rounded text-xs text-phantom-text-tertiary hover:bg-phantom-panel cursor-pointer">7d</span>
              <span className="px-2 py-1 rounded text-xs text-phantom-text-tertiary hover:bg-phantom-panel cursor-pointer">30d</span>
            </div>
          </div>
          <div className="flex-1 min-h-[240px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={scanData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--color-phantom-cyan)" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="var(--color-phantom-cyan)" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: 'var(--color-phantom-text-tertiary)' }} dy={10} />
                <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: 'var(--color-phantom-text-tertiary)' }} />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'var(--color-phantom-panel)', border: '1px solid var(--color-phantom-border)', borderRadius: '8px' }}
                  itemStyle={{ color: 'var(--color-phantom-text-primary)', fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="value" stroke="var(--color-phantom-cyan)" strokeWidth={2} fillOpacity={1} fill="url(#colorValue)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Breakdown */}
        <div className="bg-phantom-surface border border-phantom-border rounded-xl p-5 flex flex-col shadow-sm">
          <h2 className="text-sm font-semibold text-phantom-text-secondary mb-6">Open Vulnerabilities</h2>
          <div className="flex-1 flex flex-col justify-center">
            <div className="space-y-4">
              {vulnData.map((item, index) => (
                <div key={item.name} className="flex items-center justify-between group">
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                    <span className="text-sm font-medium text-phantom-text-primary">{item.name}</span>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className="text-sm font-mono text-phantom-text-secondary">{item.value}</span>
                    <div className="w-24 h-1.5 bg-phantom-panel border border-phantom-border rounded-full overflow-hidden">
                      <motion.div 
                        initial={{ width: 0 }}
                        animate={{ width: `${(item.value / 312) * 100}%` }}
                        transition={{ duration: 1, delay: index * 0.1, ease: 'easeOut' }}
                        className="h-full rounded-full"
                        style={{ backgroundColor: item.color }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-8 pt-4 border-t border-phantom-border">
               <button className="text-xs text-phantom-cyan hover:text-phantom-text-primary transition-colors flex items-center gap-1">
                 View complete findings matrix <ArrowUpRight size={12} />
               </button>
            </div>
          </div>
        </div>
      </div>

      {/* Activity / Logs */}
      <div className="mt-2">
        <h2 className="text-sm font-semibold text-phantom-text-secondary mb-4">Latest Activity</h2>
        <div className="border border-phantom-border rounded-xl bg-phantom-surface overflow-hidden">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-phantom-border">
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Status</th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Target</th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Type</th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Duration</th>
                <th className="px-4 py-3 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider text-right">Time</th>
              </tr>
            </thead>
            <tbody className="text-sm">
              <ActivityRow status="running" target="api.internal.corp" type="Deep Scan" duration="45m (running)" time="Just now" />
              <ActivityRow status="completed" target="auth.prod.gateway" type="Quick Scan" duration="12m 4s" time="2h ago" />
              <ActivityRow status="failed" target="legacy-db-01" type="Dependency Check" duration="2m 1s" time="4h ago" />
              <ActivityRow status="completed" target="cdn.global.assets" type="Subdomain Enum" duration="18m 22s" time="5h ago" />
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function MetricCard({ title, value, trend, icon: Icon, color, trendDownIsGood }: any) {
  const isPositive = trend.startsWith('+');
  const isGood = trendDownIsGood ? !isPositive : isPositive;
  
  return (
    <motion.div 
      whileHover={{ y: -2 }}
      className="bg-phantom-surface border border-phantom-border rounded-xl p-5 shadow-sm group"
    >
      <div className="flex items-start justify-between mb-4">
        <div className={cn("p-2 rounded-lg bg-phantom-panel border border-phantom-border", color)}>
          <Icon size={18} />
        </div>
        <div className={cn(
          "flex items-center gap-1 text-xs font-mono px-2 py-0.5 rounded",
          isGood ? "text-phantom-cyan bg-phantom-cyan/10" : "text-phantom-coral bg-phantom-coral/10"
        )}>
          {isPositive ? <ArrowUpRight size={12} /> : <ArrowDownRight size={12} />}
          {trend}
        </div>
      </div>
      <div>
        <div className="text-2xl font-semibold tracking-tight text-phantom-text-primary">{value}</div>
        <div className="text-sm text-phantom-text-secondary mt-0.5">{title}</div>
      </div>
    </motion.div>
  );
}

function ActivityRow({ status, target, type, duration, time }: any) {
  let StatusIcon = Clock;
  let statusColor = "text-phantom-text-tertiary";
  
  if (status === 'running') {
    StatusIcon = Zap;
    statusColor = "text-phantom-cyan animate-pulse";
  } else if (status === 'completed') {
    StatusIcon = CheckCircle;
    statusColor = "text-phantom-text-secondary";
  } else if (status === 'failed') {
    StatusIcon = AlertTriangle;
    statusColor = "text-phantom-coral";
  }

  return (
    <tr className="border-b border-phantom-border last:border-0 table-row-hover transition-colors cursor-pointer group">
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <StatusIcon size={14} className={statusColor} />
          <span className="capitalize text-phantom-text-secondary group-hover:text-phantom-text-primary transition-colors">{status}</span>
        </div>
      </td>
      <td className="px-4 py-3 font-mono text-xs">{target}</td>
      <td className="px-4 py-3 text-phantom-text-secondary">{type}</td>
      <td className="px-4 py-3 text-phantom-text-tertiary text-xs">{duration}</td>
      <td className="px-4 py-3 text-right text-phantom-text-tertiary text-xs">{time}</td>
    </tr>
  );
}
