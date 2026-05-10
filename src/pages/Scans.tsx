import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Play, Plus, Search, Calendar, ChevronRight } from 'lucide-react';
import { cn } from '../lib/utils';

export default function Scans() {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col h-full bg-phantom-bg">
      <div className="flex-none p-6 border-b border-phantom-border bg-phantom-surface/50 backdrop-blur-xl z-10 sticky top-0">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-xl font-semibold tracking-tight">Scan Execution</h1>
          <button 
            onClick={() => navigate('/scans/live')}
            className="flex items-center gap-2 px-4 py-2 bg-phantom-text-primary text-black rounded-md text-sm font-medium hover:opacity-90 transition-opacity"
          >
            <Play size={14} className="fill-black" />
            New Scan
          </button>
        </div>
      </div>

      <div className="p-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
           <TemplateCard title="Deep Infrastructure Scan" description="Comprehensive port scan, OS detection, and full CVE check against known databases." icon={ServerIcon} time="~45m" />
           <TemplateCard title="Web App Quick Scan" description="OWASP Top 10 focus. Scans for XSS, SQLi, and common misconfigurations." icon={GlobeIcon} time="~15m" />
           <TemplateCard title="Cloud Compliance" description="Specifically targets AWS/GCP/Azure control planes for IAM and storage misconfigs." icon={CloudIcon} time="~30m" />
        </div>

        <h2 className="text-sm font-semibold text-phantom-text-secondary mb-4">Recent Scans</h2>
        <div className="border border-phantom-border rounded-xl bg-phantom-surface p-4 text-center text-phantom-text-secondary py-12">
            View scan history or start a new scan above.
        </div>
      </div>
    </div>
  );
}

function TemplateCard({ title, description, time }: any) {
  return (
    <button className="flex flex-col text-left p-5 rounded-xl border border-phantom-border bg-phantom-surface hover:border-phantom-border-strong hover:bg-phantom-panel-hover transition-all group">
      <div className="flex justify-between w-full mb-3">
        <div className="w-10 h-10 rounded-lg bg-phantom-panel flex items-center justify-center text-phantom-text-secondary group-hover:text-phantom-text-primary group-hover:bg-phantom-bg transition-colors">
          <Play size={18} />
        </div>
        <span className="text-xs font-mono text-phantom-text-tertiary px-2 py-1 bg-phantom-panel rounded">{time}</span>
      </div>
      <h3 className="font-medium text-phantom-text-primary mb-1">{title}</h3>
      <p className="text-xs text-phantom-text-secondary leading-relaxed">{description}</p>
    </button>
  );
}

function ServerIcon() { return null; }
function GlobeIcon() { return null; }
function CloudIcon() { return null; }
