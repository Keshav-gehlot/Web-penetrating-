import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { 
  Activity, Server, Crosshair, ShieldAlert, 
  BookOpen, FileText, Settings, Users, 
  Search, TerminalSquare
} from 'lucide-react';
import { cn } from '../lib/utils';
import { motion } from 'motion/react';

const NAV_ITEMS = [
  { icon: Activity, label: 'Overview', path: '/dashboard' },
  { icon: Server, label: 'Assets', path: '/assets' },
  { icon: Crosshair, label: 'Scans', path: '/scans' },
  { icon: ShieldAlert, label: 'Vulnerabilities', path: '/vulnerabilities' },
  { icon: BookOpen, label: 'Intelligence', path: '/intelligence' },
  { icon: FileText, label: 'Reports', path: '/reports' },
];

const BOTTOM_NAV_ITEMS = [
  { icon: TerminalSquare, label: 'Terminal', path: '/terminal' },
  { icon: Users, label: 'Team', path: '/team' },
  { icon: Settings, label: 'Settings', path: '/settings' },
];

export function NavigationRail() {
  return (
    <nav className="w-[68px] h-full flex flex-col items-center py-4 bg-phantom-bg border-r border-transparent flex-shrink-0 z-10">
      <div className="w-10 h-10 mb-8 rounded-lg bg-gradient-to-br from-phantom-border-strong to-phantom-panel flex items-center justify-center border border-phantom-border shadow-sm cursor-pointer group">
        <div className="w-5 h-5 relative flex items-center justify-center">
            <div className="absolute inset-x-0 h-0.5 bg-phantom-text-primary rounded-full group-hover:bg-phantom-cyan transition-colors" />
            <div className="absolute inset-y-0 w-0.5 bg-phantom-text-primary rounded-full group-hover:bg-phantom-cyan transition-colors" />
            <div className="absolute w-3 h-3 border-2 border-phantom-text-primary rounded-sm rotate-45 group-hover:border-phantom-cyan transition-colors" />
        </div>
      </div>

      <div className="flex flex-col gap-3 w-full items-center mb-6">
        <button className="w-10 h-10 rounded-xl flex items-center justify-center text-phantom-text-tertiary hover:text-phantom-text-primary hover:bg-phantom-surface transition-all duration-200">
          <Search size={20} strokeWidth={2} />
        </button>
      </div>

      <div className="flex flex-col gap-2 w-full items-center flex-1">
        {NAV_ITEMS.map((item) => (
          <NavItem key={item.path} item={item} />
        ))}
      </div>

      <div className="flex flex-col gap-2 w-full items-center mt-auto pt-4">
        {BOTTOM_NAV_ITEMS.map((item) => (
          <NavItem key={item.path} item={item} />
        ))}
        
        <div className="w-10 h-10 mt-2 rounded-full overflow-hidden border border-phantom-border cursor-pointer hover:border-phantom-text-secondary transition-colors">
          <img src="https://api.dicebear.com/7.x/notionists/svg?seed=Phantom&backgroundColor=131418" alt="User Avatar" className="w-full h-full object-cover" />
        </div>
      </div>
    </nav>
  );
}

interface NavItemProps {
  item: any;
  key?: React.Key;
}

function NavItem({ item }: NavItemProps) {
  return (
    <NavLink
      to={item.path}
      className={({ isActive }) => cn(
        "relative w-10 h-10 rounded-xl flex items-center justify-center transition-all duration-200 group",
        isActive 
          ? "text-phantom-cyan bg-phantom-cyan/10" 
          : "text-phantom-text-secondary hover:text-phantom-text-primary hover:bg-phantom-surface"
      )}
      title={item.label}
    >
      {({ isActive }) => (
        <>
          <item.icon size={20} strokeWidth={isActive ? 2.5 : 2} />
          {isActive && (
            <motion.div 
              layoutId="nav-indicator"
              className="absolute -left-3 w-1 h-5 bg-phantom-cyan rounded-r-full"
              initial={false}
              transition={{ type: "spring", stiffness: 300, damping: 30 }}
            />
          )}
        </>
      )}
    </NavLink>
  );
}
