import React, { useState } from 'react';
import { Target, MessageSquare, Pin, TerminalSquare, AlertTriangle, Play, Spline, FileJson } from 'lucide-react';
import { cn } from '../lib/utils';
import { motion } from 'motion/react';

export default function Investigation() {
  const [activeTab, setActiveTab] = useState('notes');

  return (
    <div className="flex flex-col h-full bg-phantom-bg">
      <div className="flex-none p-4 border-b border-phantom-border bg-phantom-surface z-10 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="font-mono text-xs px-2 py-1 bg-phantom-panel border border-phantom-border rounded text-phantom-text-secondary">
             WS-INV-992
          </div>
          <h1 className="text-sm font-medium tracking-tight">Active Investigation Workspace</h1>
        </div>
        <div className="flex -space-x-2">
          <Avatar seed="Alice" borderColor="border-phantom-cyan" />
          <Avatar seed="Bob" borderColor="border-phantom-border" />
          <div className="w-7 h-7 rounded-full bg-phantom-surface border border-phantom-border flex items-center justify-center text-[10px] text-phantom-text-tertiary z-10">
            +2
          </div>
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Left Side: Pinned Findings & Target */}
        <div className="w-[300px] border-r border-phantom-border bg-phantom-surface/30 p-4 flex flex-col gap-4 overflow-y-auto">
           <div>
             <h3 className="text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider mb-3">Investigation Target</h3>
             <div className="p-3 border border-phantom-border bg-phantom-panel rounded-lg mb-2">
                <div className="text-sm font-medium mb-1">api.internal.corp</div>
                <div className="text-xs font-mono text-phantom-text-secondary">10.0.12.45</div>
             </div>
           </div>

           <div>
             <h3 className="text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider mb-3 flex items-center gap-1.5"><Pin size={12}/> Pinned Findings</h3>
             <div className="space-y-2">
                <PinnedCard vulnId="VULN-9021" title="curl heap-based buffer overflow" severity="critical" active />
                <PinnedCard vulnId="VULN-8712" title="Missing Security Headers" severity="low" />
             </div>
           </div>
        </div>

        {/* Center/Right: Workspace */}
        <div className="flex-1 flex flex-col min-w-0">
          <div className="flex border-b border-phantom-border px-4 pt-2 gap-4 bg-phantom-surface/30">
            <Tab id="payload" label="Payload Resampler" active={activeTab === 'payload'} onClick={() => setActiveTab('payload')} icon={FileJson} />
            <Tab id="notes" label="Analyst Scratchpad" active={activeTab === 'notes'} onClick={() => setActiveTab('notes')} icon={TerminalSquare} />
            <Tab id="discussion" label="Team Discussion" active={activeTab === 'discussion'} onClick={() => setActiveTab('discussion')} icon={MessageSquare} />
          </div>

          <div className="flex-1 bg-phantom-bg overflow-y-auto relative p-6">
             {activeTab === 'notes' && (
               <div className="w-full max-w-2xl">
                 <textarea 
                   className="w-full h-[500px] bg-transparent resize-none outline-none text-sm text-phantom-text-primary leading-relaxed font-mono placeholder:text-phantom-text-tertiary"
                   placeholder="Type scratchpad notes here. Supports markdown. Use / to open command menu."
                   defaultValue={`# Analysis of CVE-2023-38545\n\nTarget is responding to normal packets, however when injecting the malformed SOCKS5 payload through the secondary auth gateway, we see a core dump.\n\nTodo:\n- [x] Verify remote crash\n- [ ] Attempt address leak\n- [ ] Check if ASLR is bypassing`}
                 />
               </div>
             )}

             {activeTab === 'payload' && (
               <div className="flex h-full gap-4">
                  <div className="flex-1 border border-phantom-border rounded-lg bg-phantom-panel flex flex-col">
                     <div className="p-2 border-b border-phantom-border text-xs font-medium text-phantom-text-secondary">Original Request</div>
                     <textarea className="flex-1 bg-transparent p-4 outline-none font-mono text-xs text-phantom-text-tertiary resize-none" defaultValue={`POST /v1/auth HTTP/1.1\nHost: api.int\n\n{"user":"admin"}`} />
                  </div>
                  <div className="w-12 flex flex-col items-center justify-center gap-2">
                     <button className="p-2 rounded bg-phantom-cyan/10 text-phantom-cyan border border-phantom-cyan/20 hover:bg-phantom-cyan/20 transition-colors"><Play size={16} /></button>
                     <button className="p-2 rounded bg-phantom-surface text-phantom-text-tertiary border border-phantom-border hover:text-phantom-text-primary transition-colors"><Spline size={16} /></button>
                  </div>
                  <div className="flex-1 border border-phantom-border rounded-lg bg-phantom-panel flex flex-col">
                     <div className="p-2 border-b border-phantom-border text-xs font-medium text-phantom-text-secondary">Response</div>
                     <div className="flex-1 p-4 font-mono text-xs text-phantom-coral">500 Internal Server Error</div>
                  </div>
               </div>
             )}
          </div>
        </div>
      </div>
    </div>
  );
}

function PinnedCard({ vulnId, title, severity, active }: any) {
  return (
    <div className={cn(
      "p-3 border rounded-lg cursor-pointer transition-colors",
      active ? "bg-phantom-panel border-phantom-border-strong text-phantom-text-primary" : "bg-transparent border-phantom-border text-phantom-text-secondary hover:bg-phantom-panel"
    )}>
       <div className="flex items-center gap-2 mb-1">
         <span className="text-[10px] uppercase font-bold text-phantom-coral">{severity}</span>
         <span className="font-mono text-[10px] text-phantom-text-tertiary">{vulnId}</span>
       </div>
       <div className="text-xs font-medium truncate">{title}</div>
    </div>
  );
}

function Tab({ label, active, onClick, icon: Icon }: any) {
  return (
    <button 
      onClick={onClick}
      className={cn(
        "flex items-center gap-2 px-3 py-2 text-xs font-medium capitalize border-b-2 transition-colors focus:outline-none mb-[-1px]",
        active ? "border-phantom-cyan text-phantom-text-primary" : "border-transparent text-phantom-text-tertiary hover:text-phantom-text-secondary hover:border-phantom-border-strong"
      )}
    >
      <Icon size={14} /> {label}
    </button>
  );
}

function Avatar({ seed, borderColor }: { seed: string, borderColor: string }) {
  return (
    <div className={cn("w-7 h-7 rounded-full overflow-hidden border-2 z-20 relative bg-phantom-panel", borderColor)}>
      <img src={`https://api.dicebear.com/7.x/notionists/svg?seed=${seed}&backgroundColor=131418`} alt="Avatar" className="w-full h-full object-cover" />
    </div>
  );
}
