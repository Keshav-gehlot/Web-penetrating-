import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Play, Plus, Search, Calendar, ChevronRight, Server as ServerIcon, Globe as GlobeIcon, Cloud as CloudIcon, Shield, FileText, CheckCircle2 } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from '../lib/utils';

export default function Scans() {
  const navigate = useNavigate();
  const [isWizardOpen, setIsWizardOpen] = useState(false);

  return (
    <div className="flex flex-col h-full bg-phantom-bg">
      <div className="flex-none p-6 border-b border-phantom-border bg-phantom-surface/50 backdrop-blur-xl z-10 sticky top-0">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-xl font-semibold tracking-tight">Scan Execution</h1>
          <button 
            onClick={() => setIsWizardOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-phantom-text-primary text-black rounded-md text-sm font-medium hover:opacity-90 transition-opacity"
          >
            <Play size={14} className="fill-black" />
            New Scan
          </button>
        </div>
      </div>

      <div className="p-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
           <TemplateCard 
             title="Deep Infrastructure Scan" 
             description="Comprehensive port scan, OS detection, and full CVE check against known databases." 
             icon={ServerIcon} 
             time="~45m" 
             onClick={() => setIsWizardOpen(true)}
           />
           <TemplateCard 
             title="Web App Quick Scan" 
             description="OWASP Top 10 focus. Scans for XSS, SQLi, and common misconfigurations." 
             icon={GlobeIcon} 
             time="~15m" 
             onClick={() => setIsWizardOpen(true)}
           />
           <TemplateCard 
             title="Cloud Compliance" 
             description="Specifically targets AWS/GCP/Azure control planes for IAM and storage misconfigs." 
             icon={CloudIcon} 
             time="~30m" 
             onClick={() => setIsWizardOpen(true)}
           />
        </div>

        <h2 className="text-sm font-semibold text-phantom-text-secondary mb-4">Recent Scans</h2>
        <div className="border border-phantom-border rounded-xl bg-phantom-surface p-4 text-center text-phantom-text-secondary py-12">
            View scan history or start a new scan above.
        </div>
      </div>
      
      <ScanWizard isOpen={isWizardOpen} onClose={() => setIsWizardOpen(false)} onLaunch={() => navigate('/scans/live')} />
    </div>
  );
}

function TemplateCard({ title, description, time, icon: Icon, onClick }: any) {
  return (
    <button onClick={onClick} className="flex flex-col text-left p-5 rounded-xl border border-phantom-border bg-phantom-surface hover:border-phantom-border-strong hover:bg-phantom-panel-hover transition-all group">
      <div className="flex justify-between w-full mb-3">
        <div className="w-10 h-10 rounded-lg bg-phantom-panel flex items-center justify-center text-phantom-text-secondary group-hover:text-phantom-text-primary group-hover:bg-phantom-bg transition-colors border border-phantom-border">
          <Icon size={18} />
        </div>
        <span className="text-xs font-mono text-phantom-text-tertiary px-2 py-1 bg-phantom-panel rounded border border-phantom-border group-hover:text-phantom-text-secondary transition-colors">{time}</span>
      </div>
      <h3 className="font-medium text-phantom-text-primary mb-1">{title}</h3>
      <p className="text-xs text-phantom-text-secondary leading-relaxed">{description}</p>
    </button>
  );
}

function ScanWizard({ isOpen, onClose, onLaunch }: { isOpen: boolean, onClose: () => void, onLaunch: () => void }) {
  const [step, setStep] = useState(1);
  const totalSteps = 3;

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-phantom-bg/80 backdrop-blur-sm z-[100] transition-opacity"
            onClick={onClose}
          />
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 pointer-events-none">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              transition={{ type: 'spring', stiffness: 300, damping: 30 }}
              className="w-full max-w-3xl bg-phantom-panel border border-phantom-border rounded-xl shadow-2xl overflow-hidden pointer-events-auto flex flex-col h-[600px]"
            >
              {/* Header */}
              <div className="flex items-center px-6 py-4 border-b border-phantom-border bg-phantom-surface">
                 <div className="p-2 rounded bg-phantom-bg border border-phantom-border mr-4">
                    <Shield size={20} className="text-phantom-cyan" />
                 </div>
                 <div>
                    <h2 className="text-lg font-semibold text-phantom-text-primary">Configure Scan Target</h2>
                    <p className="text-sm text-phantom-text-tertiary">Set up your assessment parameters</p>
                 </div>
                 
                 <div className="ml-auto flex gap-2">
                    {[1, 2, 3].map(i => (
                      <div key={i} className={cn(
                        "w-2.5 h-2.5 rounded-full transition-colors",
                        step >= i ? "bg-phantom-cyan" : "bg-phantom-surface border border-phantom-border"
                      )} />
                    ))}
                 </div>
              </div>

              {/* Body */}
              <div className="flex-1 overflow-y-auto p-6 relative">
                 <AnimatePresence mode="wait">
                    {step === 1 && (
                      <motion.div key="step1" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} className="space-y-6">
                        <h3 className="text-sm font-medium text-phantom-text-secondary uppercase tracking-wider">Select Targets</h3>
                        <div className="space-y-4">
                          <label className="block">
                            <span className="text-sm text-phantom-text-primary mb-2 block">Target Hostname, IP, or CIDR</span>
                            <input type="text" placeholder="e.g., 10.0.0.0/24 or app.example.com" className="w-full bg-phantom-bg border border-phantom-border rounded-lg px-4 py-2 text-sm text-phantom-text-primary focus:outline-none focus:border-phantom-cyan transition-colors" defaultValue="api.internal.corp" />
                          </label>
                          <div className="border border-phantom-border border-dashed rounded-lg p-6 flex flex-col items-center justify-center text-center bg-phantom-surface/50 hover:bg-phantom-surface cursor-pointer transition-colors">
                             <FileText className="text-phantom-text-tertiary mb-2" size={24} />
                             <p className="text-sm text-phantom-text-primary font-medium">Upload target list</p>
                             <p className="text-xs text-phantom-text-tertiary">CSV or TXT files up to 10MB</p>
                          </div>
                        </div>
                      </motion.div>
                    )}
                    
                    {step === 2 && (
                      <motion.div key="step2" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} className="space-y-6">
                        <h3 className="text-sm font-medium text-phantom-text-secondary uppercase tracking-wider">Select Profile</h3>
                        <div className="grid grid-cols-2 gap-4">
                          <ProfileOption title="Lightweight Scan" desc="Passive discovery, no intrusive payloads." selected={false} />
                          <ProfileOption title="Deep Infrastructure" desc="Full port scan, vulnerabilities." selected={true} />
                          <ProfileOption title="OWASP Top 10" desc="Focused on common web application flaws." selected={false} />
                          <ProfileOption title="Compliance (PCI-DSS)" desc="Strict checks for compliance requirements." selected={false} />
                        </div>
                      </motion.div>
                    )}

                    {step === 3 && (
                      <motion.div key="step3" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} className="space-y-6">
                         <h3 className="text-sm font-medium text-phantom-text-secondary uppercase tracking-wider">Review & Launch</h3>
                         <div className="bg-phantom-bg border border-phantom-border rounded-xl p-5 space-y-4">
                            <ReviewRow label="Targets" value="api.internal.corp" />
                            <ReviewRow label="Scan Profile" value="Deep Infrastructure" />
                            <ReviewRow label="Schedule" value="Run immediately" />
                            <ReviewRow label="Notifications" value="Slack: #security-alerts" />
                         </div>
                      </motion.div>
                    )}
                 </AnimatePresence>
              </div>

              {/* Footer */}
              <div className="flex items-center justify-between px-6 py-4 border-t border-phantom-border bg-phantom-surface">
                 <button onClick={onClose} className="px-4 py-2 text-sm text-phantom-text-secondary hover:text-phantom-text-primary transition-colors focus:outline-none">Cancel</button>
                 <div className="flex gap-3">
                   {step > 1 && (
                     <button onClick={() => setStep(s => s - 1)} className="px-4 py-2 rounded-md border border-phantom-border bg-phantom-bg text-sm text-phantom-text-secondary hover:text-phantom-text-primary transition-colors focus:outline-none">
                       Back
                     </button>
                   )}
                   {step < totalSteps ? (
                     <button onClick={() => setStep(s => s + 1)} className="px-4 py-2 rounded-md bg-phantom-text-primary text-black text-sm font-medium hover:opacity-90 transition-opacity focus:outline-none">
                       Next Step
                     </button>
                   ) : (
                     <button onClick={onLaunch} className="px-4 py-2 rounded-md bg-phantom-cyan text-phantom-bg text-sm font-medium hover:opacity-90 transition-opacity flex items-center gap-2 focus:outline-none shadow-[0_0_15px_rgba(52,211,153,0.3)]">
                       <Play size={14} className="fill-phantom-bg" /> Launch Scan
                     </button>
                   )}
                 </div>
              </div>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
}

function ProfileOption({ title, desc, selected }: any) {
  return (
    <div className={cn(
      "border p-4 rounded-xl cursor-pointer transition-all",
      selected ? "border-phantom-cyan bg-phantom-cyan/5" : "border-phantom-border bg-phantom-bg hover:border-phantom-text-tertiary"
    )}>
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-sm font-medium text-phantom-text-primary">{title}</h4>
        {selected && <CheckCircle2 size={16} className="text-phantom-cyan" />}
      </div>
      <p className="text-xs text-phantom-text-secondary leading-relaxed">{desc}</p>
    </div>
  );
}

function ReviewRow({ label, value }: any) {
  return (
    <div className="flex justify-between items-center py-2 border-b border-phantom-border/50 last:border-0 last:pb-0">
      <span className="text-sm text-phantom-text-tertiary">{label}</span>
      <span className="text-sm font-medium text-phantom-text-primary">{value}</span>
    </div>
  );
}
