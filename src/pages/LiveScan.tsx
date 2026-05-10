import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Terminal as TerminalIcon, StopCircle } from 'lucide-react';
import { motion } from 'motion/react';

const mockLogs = [
  "[10:22:01] Initializing scan engine (v4.2.1-rc)...",
  "[10:22:01] Resolving targets for api.internal.corp...",
  "[10:22:02] Target resolved to 10.0.12.45.",
  "[10:22:02] Loading plugin 'port_enum'...",
  "[10:22:05] Discovered open port: 80/tcp (http)",
  "[10:22:05] Discovered open port: 443/tcp (https)",
  "[10:22:08] Loading plugin 'ssl_cipher_check'...",
  "[10:22:15] Warning: Weak cipher DES-CBC3-SHA allowed on 443/tcp",
  "[10:22:18] Loading plugin 'http_vuln_scan'...",
  "[10:22:25] Fuzzing parameters on /login...",
];

export default function LiveScan() {
  const navigate = useNavigate();
  const [logs, setLogs] = useState<string[]>([]);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    let currentIndex = 0;
    const interval = setInterval(() => {
      if (currentIndex < mockLogs.length) {
        setLogs(prev => [...prev, mockLogs[currentIndex]]);
        setProgress(Math.floor(((currentIndex + 1) / mockLogs.length) * 100));
        currentIndex++;
      } else {
        clearInterval(interval);
      }
    }, 1200);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex flex-col h-full bg-phantom-bg">
      <div className="flex-none p-6 border-b border-phantom-border bg-phantom-surface/50 backdrop-blur-xl z-10 sticky top-0">
        <div className="flex items-center gap-4">
          <button 
            onClick={() => navigate('/scans')}
            className="p-2 rounded-md hover:bg-phantom-panel text-phantom-text-tertiary hover:text-phantom-text-primary transition-colors"
          >
            <ArrowLeft size={18} />
          </button>
          <div>
            <h1 className="text-lg font-medium tracking-tight flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-phantom-cyan animate-pulse" />
              Active Scan: Deep Infrastructure
            </h1>
            <div className="text-sm font-mono text-phantom-text-secondary mt-1">Target: api.internal.corp (10.0.12.45)</div>
          </div>
          
          <div className="ml-auto flex items-center gap-3">
             <button className="flex items-center gap-2 px-3 py-1.5 border border-phantom-border rounded-md text-sm text-phantom-text-secondary hover:text-phantom-coral hover:border-phantom-coral/30 hover:bg-phantom-coral/10 transition-colors">
               <StopCircle size={14} />
               Abort
             </button>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-hidden p-6 flex flex-col gap-6">
        <div className="bg-phantom-surface border border-phantom-border rounded-xl p-6">
          <div className="flex justify-between text-xs font-medium text-phantom-text-secondary mb-2">
            <span>Overall Progress</span>
            <span className="font-mono">{progress}%</span>
          </div>
          <div className="w-full h-1.5 bg-phantom-panel border border-phantom-border rounded-full overflow-hidden">
            <motion.div 
              className="h-full bg-phantom-cyan"
              initial={{ width: 0 }}
              animate={{ width: `${progress}%` }}
              transition={{ ease: "easeOut", duration: 0.5 }}
            />
          </div>
        </div>

        <div className="flex-1 bg-phantom-[#050505] rounded-xl border border-phantom-border flex flex-col shadow-inner overflow-hidden relative">
          <div className="flex border-b border-phantom-border bg-phantom-surface px-4 py-2 items-center gap-2 text-xs text-phantom-text-tertiary uppercase">
             <TerminalIcon size={12} />
             <span>Execution Log</span>
          </div>
          <div className="p-4 flex-1 overflow-y-auto font-mono text-sm leading-relaxed space-y-1">
            {logs.map((log, i) => (
              <motion.div 
                key={i}
                initial={{ opacity: 0, x: -5 }}
                animate={{ opacity: 1, x: 0 }}
                className={
                  log.includes('Warning') 
                    ? 'text-phantom-amber' 
                    : log.includes('error') ? 'text-phantom-coral' : 'text-phantom-text-secondary'
                }
              >
                {log}
              </motion.div>
            ))}
            {progress < 100 && (
              <motion.div 
                animate={{ opacity: [1, 0, 1] }} 
                transition={{ repeat: Infinity, duration: 1.5 }}
                className="w-2 h-4 bg-phantom-text-secondary mt-2 inline-block align-middle"
              />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
