import React from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { NavigationRail } from './layout/NavigationRail';
import { SecondarySidebar } from './layout/SecondarySidebar';
import { CommandPalette } from './layout/CommandPalette';
import { KeyboardShortcuts } from './layout/KeyboardShortcuts';

import Dashboard from './pages/Dashboard';
import AssetManagement from './pages/AssetManagement';
import Vulnerabilities from './pages/Vulnerabilities';
import Scans from './pages/Scans';
import LiveScan from './pages/LiveScan';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import Topology from './pages/Topology';
import Investigation from './pages/Investigation';

function Placeholder() {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center h-full w-full">
       <div className="w-16 h-16 rounded-2xl bg-phantom-panel border border-phantom-border flex items-center justify-center mb-6">
          <div className="w-6 h-6 border-2 border-dashed border-phantom-text-tertiary rounded-full animate-[spin_4s_linear_infinite]" />
       </div>
       <h2 className="text-xl font-medium text-phantom-text-primary mb-2">Coming Soon</h2>
       <p className="text-phantom-text-secondary text-sm max-w-sm">This module is part of the extensive Phantom Cyber suite, currently under deployment.</p>
    </div>
  );
}

export default function App() {
  const location = useLocation();
  const isLoginPage = location.pathname === '/login';

  if (isLoginPage) {
    return (
      <Routes>
        {/* <Route path="/login" element={<Login />} /> */}
      </Routes>
    );
  }

  return (
    <div className="flex h-screen w-full bg-phantom-bg text-phantom-text-primary overflow-hidden">
      <NavigationRail />
      <SecondarySidebar />
      
      <main className="flex-1 flex flex-col min-w-0 h-full relative overflow-hidden bg-phantom-bg rounded-l-xl border border-phantom-border ring-1 ring-white/5 my-2 mr-2 shadow-2xl">
        <div className="flex-1 overflow-y-auto w-full h-full">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/assets" element={<AssetManagement />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/live" element={<LiveScan />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/topology" element={<Topology />} />
            <Route path="/investigation" element={<Investigation />} />
            <Route path="*" element={<Placeholder />} />
          </Routes>
        </div>
      </main>

      <CommandPalette />
      <KeyboardShortcuts />
    </div>
  );
}
