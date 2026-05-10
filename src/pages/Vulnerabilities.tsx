import React, { useState } from 'react';
import { Search, Filter, AlertTriangle, ArrowRight, X, Copy, CheckCircle2, FileJson, Clock, BookOpen } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from '../lib/utils';

const vulns = [
  { id: 'VULN-9021', cve: 'CVE-2023-38545', title: 'curl heap-based buffer overflow', severity: 'critical', status: 'open', age: '2d', asset: 'api.internal.corp', viewers: ['Alice', 'Bob'] },
  { id: 'VULN-9020', cve: 'CVE-2023-44487', title: 'HTTP/2 Rapid Reset Attack', severity: 'critical', status: ' investigating', age: '5d', asset: 'auth.prod.gateway', viewers: [] },
  { id: 'VULN-8942', cve: 'CVE-2021-44228', title: 'Log4Shell in legacy auth', severity: 'high', status: 'open', age: '14d', asset: 'legacy-db-01', viewers: ['Charlie'] },
  { id: 'VULN-8810', cve: 'N/A', title: 'Exposed Management Interface', severity: 'high', status: 'remediation', age: '21d', asset: 'k8s-worker-01', viewers: [] },
  { id: 'VULN-8755', cve: 'CVE-2022-26809', title: 'RPC Endpoint Mapper bypass', severity: 'medium', status: 'open', age: '30d', asset: 'cdn.global.assets', viewers: [] },
  { id: 'VULN-8712', cve: 'N/A', title: 'Missing Security Headers', severity: 'low', status: 'ignored', age: '45d', asset: 'api.internal.corp', viewers: [] },
];

export default function Vulnerabilities() {
  const [selectedVuln, setSelectedVuln] = useState<any>(null);

  return (
    <div className="flex h-full bg-phantom-bg relative overflow-hidden">
      <div className={cn("flex flex-col h-full flex-1 transition-all duration-300", selectedVuln ? "md:pr-[480px]" : "")}>
        <div className="flex-none p-6 border-b border-phantom-border bg-phantom-surface/50 backdrop-blur-xl z-10 sticky top-0">
          <div className="flex items-center justify-between mb-4">
            <h1 className="text-xl font-semibold tracking-tight">Vulnerability Findings</h1>
            <div className="flex gap-2">
              <button className="px-3 py-1.5 bg-phantom-panel border border-phantom-border rounded-md text-sm hover:text-phantom-text-primary transition-colors hover:bg-phantom-panel-hover focus:outline-none">Export CSV</button>
              <button className="px-3 py-1.5 bg-phantom-text-primary text-black rounded-md text-sm font-medium hover:opacity-90 transition-opacity focus:outline-none">Create Report</button>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-phantom-text-tertiary" size={16} />
              <input 
                type="text" 
                placeholder="Search CVE, title, or asset..." 
                className="w-full bg-phantom-panel border border-phantom-border rounded-lg pl-9 pr-4 py-2 text-sm focus:outline-none focus:border-phantom-cyan transition-colors"
              />
            </div>
            <button className="flex items-center gap-2 px-3 py-2 bg-phantom-panel border border-phantom-border rounded-lg text-sm text-phantom-text-secondary hover:text-phantom-text-primary transition-colors focus:outline-none">
              <Filter size={14} />
              Severity: Critical, High
            </button>
            <div className="ml-auto flex items-center bg-phantom-panel rounded-lg border border-phantom-border p-1">
              <button className="px-3 py-1 bg-phantom-surface rounded text-xs text-phantom-text-primary font-medium focus:outline-none shadow-sm">Analyst</button>
              <button className="px-3 py-1 rounded text-xs text-phantom-text-tertiary hover:text-phantom-text-primary focus:outline-none">Executive</button>
            </div>
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
                </tr>
              </thead>
              <tbody className="text-sm cursor-default">
                {vulns.map((vuln) => (
                  <tr 
                    key={vuln.id} 
                    onClick={() => setSelectedVuln(vuln)}
                    className={cn(
                      "border-b border-phantom-border last:border-0 table-row-hover transition-colors group cursor-pointer",
                      selectedVuln?.id === vuln.id ? "bg-phantom-panel border-l-2 border-l-phantom-cyan" : "border-l-2 border-l-transparent"
                    )}
                  >
                    <td className="px-4 py-3 pl-6" onClick={e => e.stopPropagation()}>
                      <input type="checkbox" className="rounded border-phantom-border bg-phantom-panel w-4 h-4 accent-phantom-cyan cursor-pointer" />
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-mono text-xs text-phantom-text-primary">{vuln.id}</div>
                      <div className="font-mono text-[10px] text-phantom-text-tertiary mt-0.5">{vuln.cve}</div>
                    </td>
                    <td className="px-4 py-3">
                       <div className="font-medium text-phantom-text-primary mb-1">{vuln.title}</div>
                       <div className="text-xs text-phantom-text-secondary font-mono flex items-center gap-2">
                         {vuln.asset}
                         {vuln.viewers.length > 0 && (
                           <div className="flex -space-x-1.5 ml-2 border-l border-phantom-border pl-2">
                             {vuln.viewers.map(viewer => (
                               <div key={viewer} className="w-4 h-4 rounded-full overflow-hidden border border-phantom-panel relative" title={`${viewer} is viewing`}>
                                 <div className="absolute inset-x-0 bottom-0 top-1/2 bg-phantom-cyan/20 blur-[2px]" />
                                 <img src={`https://api.dicebear.com/7.x/notionists/svg?seed=${viewer}&backgroundColor=131418`} alt="viewer" />
                               </div>
                             ))}
                           </div>
                         )}
                       </div>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={vuln.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <span className="capitalize text-xs text-phantom-text-secondary bg-phantom-bg border border-phantom-border px-2 py-1 rounded">{vuln.status}</span>
                    </td>
                    <td className="px-4 py-3 text-phantom-text-tertiary text-xs">{vuln.age}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <AnimatePresence>
        {selectedVuln && (
          <motion.div 
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: "spring", stiffness: 300, damping: 30 }}
            className="absolute top-0 right-0 bottom-0 w-[480px] bg-phantom-panel border-l border-phantom-border shadow-2xl z-20 flex flex-col"
          >
             <EvidencePanel vuln={selectedVuln} onClose={() => setSelectedVuln(null)} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function EvidencePanel({ vuln, onClose }: { vuln: any, onClose: () => void }) {
  const [activeTab, setActiveTab] = useState('evidence');

  return (
    <>
      <div className="flex items-center justify-between p-4 border-b border-phantom-border bg-phantom-surface">
         <div>
            <div className="flex items-center gap-2 mb-1">
               <span className="font-mono text-xs text-phantom-text-tertiary px-1.5 py-0.5 rounded bg-phantom-bg border border-phantom-border">{vuln.id}</span>
               <SeverityBadge severity={vuln.severity} />
            </div>
            <h2 className="text-base font-semibold text-phantom-text-primary">{vuln.title}</h2>
         </div>
         <div className="flex items-center gap-4">
           {vuln.viewers.length > 0 && (
             <div className="flex -space-x-2">
               {vuln.viewers.map((viewer: string) => (
                 <div key={viewer} className="w-6 h-6 rounded-full overflow-hidden border-2 border-phantom-surface bg-phantom-panel" title={viewer}>
                   <img src={`https://api.dicebear.com/7.x/notionists/svg?seed=${viewer}&backgroundColor=131418`} alt="viewer" />
                 </div>
               ))}
             </div>
           )}
           <button onClick={onClose} className="p-2 text-phantom-text-tertiary hover:text-phantom-text-primary rounded-md hover:bg-phantom-bg transition-colors focus:outline-none">
             <X size={18} />
           </button>
         </div>
      </div>

      <div className="flex border-b border-phantom-border px-4 pt-2 gap-4">
        {['overview', 'evidence', 'discussion', 'activity'].map(tab => (
          <button 
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={cn(
              "px-1 py-2 text-xs font-medium capitalize border-b-2 transition-colors focus:outline-none",
              activeTab === tab ? "border-phantom-cyan text-phantom-text-primary" : "border-transparent text-phantom-text-tertiary hover:text-phantom-text-secondary"
            )}
          >
            {tab}
            {tab === 'discussion' && <span className="ml-1.5 px-1 py-0.5 bg-phantom-panel text-[9px] rounded-full text-phantom-text-primary border border-phantom-border">2</span>}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        {activeTab === 'evidence' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-sm font-medium text-phantom-text-primary mb-3 flex items-center gap-2"><FileJson size={14} className="text-phantom-text-tertiary"/> Request Payload</h3>
              <div className="relative group">
                <button className="absolute top-2 right-2 p-1.5 rounded bg-phantom-surface border border-phantom-border text-phantom-text-tertiary opacity-0 group-hover:opacity-100 transition-opacity hover:text-phantom-text-primary focus:outline-none">
                  <Copy size={12} />
                </button>
                <pre className="bg-[#0a0a0c] border border-phantom-border rounded-lg p-4 font-mono text-[11px] leading-relaxed text-phantom-text-secondary overflow-x-auto">
{`POST /api/v1/auth/login HTTP/1.1
Host: ${vuln.asset}
User-Agent: curl/8.4.0
Accept: */*
Content-Length: 154
Content-Type: application/json

{"username":"admin","password":"${'A'.repeat(80)}..."}`}
                </pre>
              </div>
            </div>

            <div>
              <h3 className="text-sm font-medium text-phantom-text-primary mb-3 flex items-center gap-2"><FileJson size={14} className="text-phantom-text-tertiary"/> Server Response</h3>
              <div className="relative group">
                <button className="absolute top-2 right-2 p-1.5 rounded bg-phantom-surface border border-phantom-border text-phantom-text-tertiary opacity-0 group-hover:opacity-100 transition-opacity hover:text-phantom-text-primary focus:outline-none">
                  <Copy size={12} />
                </button>
                <pre className="bg-[#0a0a0c] border border-phantom-border border-l-2 border-l-phantom-coral rounded-lg p-4 font-mono text-[11px] leading-relaxed text-phantom-text-secondary overflow-x-auto">
{`HTTP/1.1 500 Internal Server Error
Date: Thu, 12 Oct 2023 10:22:15 GMT
Content-Type: application/json
Content-Length: 128
Connection: close

{"error":"Segmentation fault (core dumped)","trace":"libc.so.6+0x4c2a0..."}`}
                </pre>
              </div>
            </div>
            
            <div className="p-4 rounded-lg bg-phantom-surface border border-phantom-border">
               <h4 className="text-xs font-medium text-phantom-text-primary mb-1">Analyst Notes</h4>
               <p className="text-xs text-phantom-text-tertiary italic">"Confirmed crash. The service restarts automatically but this is highly exploitable for DoS or potential RCE." - Security Automation</p>
            </div>
          </div>
        )}

        {activeTab === 'overview' && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
               <div className="p-3 rounded-lg bg-phantom-surface border border-phantom-border">
                 <div className="text-[10px] text-phantom-text-tertiary uppercase tracking-wider mb-1">CVSS Score</div>
                 <div className="text-lg font-mono text-phantom-coral">9.8</div>
               </div>
               <div className="p-3 rounded-lg bg-phantom-surface border border-phantom-border">
                 <div className="text-[10px] text-phantom-text-tertiary uppercase tracking-wider mb-1">Affected Asset</div>
                 <div className="text-sm font-mono text-phantom-text-primary">{vuln.asset}</div>
               </div>
            </div>
            <div>
               <h3 className="text-sm font-medium text-phantom-text-primary mb-2">Description</h3>
               <p className="text-sm text-phantom-text-secondary leading-relaxed">
                 A heap-based buffer overflow exists in curl before version 8.4.0. The vulnerability can be triggered when curl is told to use a SOCKS5 proxy to resolve a hostname that is excessively long.
               </p>
            </div>
          </div>
        )}

        {activeTab === 'discussion' && (
          <div className="flex flex-col h-full">
            <div className="flex-1 space-y-6 pb-4">
               <div className="flex gap-3">
                  <div className="w-8 h-8 rounded-full overflow-hidden border border-phantom-border flex-none">
                     <img src="https://api.dicebear.com/7.x/notionists/svg?seed=Alice&backgroundColor=131418" alt="Alice" />
                  </div>
                  <div className="flex-1">
                     <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-medium text-phantom-text-primary">Alice Security</span>
                        <span className="text-[10px] text-phantom-text-tertiary">2h ago</span>
                     </div>
                     <p className="text-sm text-phantom-text-secondary bg-phantom-surface p-3 rounded-lg rounded-tl-none border border-phantom-border">
                       I've verified the payload locally. This instance of curl is definitely vulnerable. We need to patch the base image rather than just this deployment.
                     </p>
                  </div>
               </div>
               
               <div className="flex gap-3">
                  <div className="w-8 h-8 rounded-full overflow-hidden border border-phantom-border flex-none">
                     <img src="https://api.dicebear.com/7.x/notionists/svg?seed=Bob&backgroundColor=131418" alt="Bob" />
                  </div>
                  <div className="flex-1">
                     <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-medium text-phantom-text-primary">Bob Platform</span>
                        <span className="text-[10px] text-phantom-text-tertiary">30m ago</span>
                     </div>
                     <p className="text-sm text-phantom-text-secondary bg-phantom-surface p-3 rounded-lg rounded-tl-none border border-phantom-border">
                       I'm checking the k8s manifests now. We can probably bump the alpine base image and roll it out gracefully.
                     </p>
                  </div>
               </div>
            </div>
            <div className="mt-auto pt-4 border-t border-phantom-border">
               <div className="relative">
                 <textarea 
                   placeholder="Type a comment or / to open actions..."
                   className="w-full bg-phantom-surface border border-phantom-border rounded-lg pl-3 pr-10 py-2.5 text-sm focus:outline-none focus:border-phantom-cyan resize-none h-20 text-phantom-text-primary placeholder:text-phantom-text-tertiary"
                 />
                 <button className="absolute bottom-2 right-2 p-1.5 bg-phantom-text-primary text-black rounded hover:opacity-90">
                    <ArrowRight size={14} />
                 </button>
               </div>
            </div>
          </div>
        )}
      </div>
      
      <div className="p-4 border-t border-phantom-border bg-phantom-bg flex items-center justify-between">
         <select className="bg-phantom-surface border border-phantom-border rounded-md px-3 py-1.5 text-sm text-phantom-text-primary focus:outline-none focus:border-phantom-cyan">
           <option>Status: Open</option>
           <option>Status: Investigating</option>
           <option>Status: Auto-Remediated</option>
           <option>Status: Resolved</option>
         </select>
         <button className="px-4 py-1.5 bg-phantom-cyan rounded-md text-sm font-medium text-phantom-bg hover:opacity-90 transition-opacity focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-phantom-cyan focus:ring-offset-phantom-bg">
           Assign to Jira
         </button>
      </div>
    </>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const isCritical = severity === 'critical';
  const isHigh = severity === 'high';
  
  return (
    <div className="flex items-center gap-1.5 px-2 py-0.5 rounded border border-phantom-border bg-phantom-surface">
      <div className={cn(
        "w-1.5 h-1.5 rounded-full",
        isCritical && "bg-phantom-coral animate-pulse",
        isHigh && "bg-phantom-amber",
        severity === 'medium' && "bg-phantom-cyan",
        severity === 'low' && "bg-phantom-text-tertiary"
      )} />
      <span className={cn(
        "text-[10px] font-medium uppercase tracking-wider",
        isCritical ? "text-phantom-coral" : "text-phantom-text-secondary"
      )}>
        {severity}
      </span>
    </div>
  );
}
