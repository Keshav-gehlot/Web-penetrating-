import React from 'react';
import { useLocation } from 'react-router-dom';
import { ChevronDown, Plus, Filter, Zap, Target, Lock, AlertCircle } from 'lucide-react';
import { cn } from '../lib/utils';
import { motion, AnimatePresence } from 'motion/react';

export function SecondarySidebar() {
  const location = useLocation();
  const path = location.pathname;

  // Determine what to show based on path
  let content = null;

  if (path.startsWith('/dashboard')) {
    content = <DashboardSidebar />;
  } else if (path.startsWith('/scans')) {
    content = <ScansSidebar />;
  } else {
    // Default or common structure
    content = <DefaultSidebar title={path.split('/')[1] || 'Overview'} />;
  }

  return (
    <div className="w-[240px] h-full bg-phantom-bg flex-shrink-0 flex flex-col border-r border-transparent z-0 overflow-y-auto hidden md:flex">
      {content}
    </div>
  );
}

function DashboardSidebar() {
  return (
    <div className="flex flex-col h-full px-4 py-6">
      <div className="flex items-center justify-between mb-8">
        <button className="flex items-center gap-2 text-sm font-medium hover:text-phantom-text-primary transition-colors focus:outline-none">
          <div className="w-5 h-5 rounded bg-phantom-surface border border-phantom-border flex items-center justify-center text-xs">P</div>
          <span>Prod Env</span>
          <ChevronDown size={14} className="text-phantom-text-tertiary" />
        </button>
      </div>

      <div className="space-y-6">
        <div>
          <div className="text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider mb-3">Workspaces</div>
          <div className="space-y-1">
            <SidebarItem icon={Target} label="Production" active />
            <SidebarItem icon={Zap} label="Staging" />
            <SidebarItem icon={Lock} label="Internal Corp" />
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-3">
            <div className="text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Saved Views</div>
            <button className="text-phantom-text-tertiary hover:text-phantom-text-primary"><Plus size={14} /></button>
          </div>
          <div className="space-y-1">
            <SidebarItem icon={Filter} label="Critical Vulns" badge="12" badgeColor="text-phantom-coral" />
            <SidebarItem icon={Filter} label="Failed Scans" badge="3" />
            <SidebarItem icon={Filter} label="Recently Discovered" />
          </div>
        </div>
      </div>
    </div>
  );
}

function ScansSidebar() {
  return (
    <div className="flex flex-col h-full px-4 py-6">
      <div className="text-sm font-medium mb-8 pl-2">Scan Management</div>
      <div className="space-y-1">
        <SidebarItem icon={Zap} label="Active Scans" badge="1" active />
        <SidebarItem icon={Target} label="Schedules" />
        <SidebarItem icon={AlertCircle} label="Configurations" />
        <SidebarItem icon={Filter} label="History" />
      </div>
    </div>
  );
}

function DefaultSidebar({ title }: { title: string }) {
  return (
    <div className="flex flex-col h-full px-4 py-6">
      <div className="text-sm font-medium mb-8 capitalize pl-2">{title}</div>
      <div className="space-y-1">
        <SidebarItem icon={Target} label="All Items" active />
        <SidebarItem icon={Filter} label="Favorites" />
      </div>
    </div>
  );
}


function SidebarItem({ icon: Icon, label, active, badge, badgeColor }: any) {
  return (
    <button
      className={cn(
        "w-full flex items-center justify-between px-2 py-1.5 rounded-md text-sm transition-all duration-200 group text-left",
        active 
          ? "bg-phantom-surface text-phantom-text-primary font-medium" 
          : "text-phantom-text-secondary hover:bg-phantom-surface hover:text-phantom-text-primary"
      )}
    >
      <div className="flex items-center gap-2.5">
        <Icon size={14} className={cn(
          active ? "text-phantom-cyan" : "text-phantom-text-tertiary group-hover:text-phantom-text-secondary"
        )} />
        <span>{label}</span>
      </div>
      {badge && (
        <span className={cn("text-xs", badgeColor || "text-phantom-text-tertiary")}>
          {badge}
        </span>
      )}
    </button>
  );
}
