import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Server, Database, Globe, Network, ArrowLeft, ArrowRight, ShieldAlert, Cpu } from 'lucide-react';
import { motion } from 'motion/react';
import { cn } from '../lib/utils';

interface NodeAreaProps {
  children: React.ReactNode;
}

const NODES = [
  { id: 'n1', type: 'globe', label: 'Cloudflare Edge', status: 'secure', x: 20, y: 50 },
  { id: 'n2', type: 'gateway', label: 'Ingress Gateway', status: 'warning', x: 40, y: 50 },
  { id: 'n3', type: 'server', label: 'API Server 1', status: 'critical', x: 60, y: 30 },
  { id: 'n4', type: 'server', label: 'API Server 2', status: 'secure', x: 60, y: 70 },
  { id: 'n5', type: 'database', label: 'Primary DB', status: 'secure', x: 80, y: 50 },
];

const EDGES = [
  { source: 'n1', target: 'n2' },
  { source: 'n2', target: 'n3' },
  { source: 'n2', target: 'n4' },
  { source: 'n3', target: 'n5' },
  { source: 'n4', target: 'n5' },
];

export default function Topology() {
  return (
    <div className="flex flex-col h-full bg-phantom-bg">
      <div className="flex-none p-6 border-b border-phantom-border bg-phantom-surface/50 backdrop-blur-xl z-10 sticky top-0">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-xl font-semibold tracking-tight">Service Topology</h1>
          <div className="flex gap-2 text-xs">
             <div className="flex items-center gap-1.5 px-3 py-1 bg-phantom-panel border border-phantom-border rounded-md">
               <span className="w-2 h-2 rounded-full bg-phantom-coral" /> Critical Path
             </div>
          </div>
        </div>
      </div>

      <div className="flex-1 relative overflow-hidden bg-[url('https://transparenttextures.com/patterns/cubes.png')] bg-[length:30px_30px] bg-opacity-[0.05]">
        <div className="absolute inset-0 bg-phantom-bg/[0.97]" />
        
        {/* Draw Edges */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
           {EDGES.map((edge, i) => {
             const s = NODES.find(n => n.id === edge.source);
             const t = NODES.find(n => n.id === edge.target);
             if (!s || !t) return null;
             
             // Very simple path calculation
             return (
               <motion.path 
                 key={i}
                 initial={{ pathLength: 0, opacity: 0 }}
                 animate={{ pathLength: 1, opacity: 1 }}
                 transition={{ duration: 1.5, ease: "easeInOut", delay: i * 0.2 }}
                 d={`M ${s.x}% ${s.y}% L ${t.x}% ${t.y}%`}
                 stroke="var(--color-phantom-border-strong)"
                 strokeWidth="2"
                 fill="none"
                 className={s.status === 'critical' || t.status === 'critical' ? 'stroke-phantom-coral/50' : ''}
               />
             )
           })}
        </svg>

        {/* Draw Nodes */}
        {NODES.map((node, i) => (
          <TopologyNode key={node.id} node={node} index={i} />
        ))}
      </div>
    </div>
  );
}

function TopologyNode({ node, index }: any) {
  let Icon = Server;
  if (node.type === 'globe') Icon = Globe;
  if (node.type === 'gateway') Icon = Network;
  if (node.type === 'database') Icon = Database;

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ type: "spring", stiffness: 300, damping: 20, delay: index * 0.15 }}
      whileHover={{ scale: 1.05 }}
      className="absolute -translate-x-1/2 -translate-y-1/2 group cursor-pointer"
      style={{ left: `${node.x}%`, top: `${node.y}%` }}
    >
      <div className="flex flex-col items-center">
        <div className={cn(
          "w-12 h-12 rounded-xl flex items-center justify-center border shadow-lg backdrop-blur-md relative",
          node.status === 'critical' ? "bg-phantom-coral/10 border-phantom-coral text-phantom-coral shadow-[0_0_15px_rgba(251,113,133,0.2)]" :
          node.status === 'warning' ? "bg-phantom-amber/10 border-phantom-amber text-phantom-amber" :
          "bg-phantom-panel border-phantom-border text-phantom-text-secondary group-hover:text-phantom-text-primary group-hover:border-phantom-text-tertiary"
        )}>
          {node.status === 'critical' && (
            <div className="absolute -top-1.5 -right-1.5 w-4 h-4 bg-phantom-coral rounded-full flex items-center justify-center animate-pulse">
               <ShieldAlert size={10} className="text-white" />
            </div>
          )}
          <Icon size={22} className="relative z-10" />
        </div>
        <div className="mt-3 bg-phantom-panel/80 backdrop-blur border border-phantom-border px-2.5 py-1 rounded-md shadow-sm">
          <span className="text-[11px] font-medium whitespace-nowrap text-phantom-text-primary">{node.label}</span>
        </div>
      </div>
    </motion.div>
  );
}
