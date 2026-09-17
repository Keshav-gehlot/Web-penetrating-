import React from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { NavigationRail } from './layout/NavigationRail';
import { SecondarySidebar } from './layout/SecondarySidebar';
import { CommandPalette } from './layout/CommandPalette';
import { KeyboardShortcuts } from './layout/KeyboardShortcuts';
import { getSession } from './lib/auth';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import AssetManagement from './pages/AssetManagement';
import Vulnerabilities from './pages/Vulnerabilities';
import Scans from './pages/Scans';
import LiveScan from './pages/LiveScan';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import Topology from './pages/Topology';
import Investigation from './pages/Investigation';
import OSINT from './pages/OSINT';
import AuditLogs from './pages/AuditLogs';
import Team from './pages/Team';
import Terminal from './pages/Terminal';
import NetWatch from './pages/NetWatch';
import SystemStatus from './pages/SystemStatus';
import Schedules from './pages/Schedules';
import ScopeManager from './pages/ScopeManager';
function Protected(){const location=useLocation();const session=getSession();if(!session)return <Navigate to={`/login?next=${encodeURIComponent(location.pathname+location.search)}`} replace/>;return <div className="flex h-screen w-full bg-phantom-bg text-phantom-text-primary overflow-hidden"><NavigationRail/><SecondarySidebar/><main className="flex-1 flex flex-col min-w-0 h-full relative overflow-hidden bg-phantom-bg rounded-l-xl border border-phantom-border ring-1 ring-white/5 my-2 mr-2 shadow-2xl"><div className="flex-1 overflow-y-auto w-full h-full"><Routes><Route path="/" element={<Navigate to="/dashboard" replace/>}/><Route path="/dashboard" element={<Dashboard/>}/><Route path="/assets" element={<AssetManagement/>}/><Route path="/scope" element={<ScopeManager/>}/><Route path="/vulnerabilities" element={<Vulnerabilities/>}/><Route path="/scans" element={<Scans/>}/><Route path="/scans/live" element={<LiveScan/>}/><Route path="/schedules" element={<Schedules/>}/><Route path="/reports" element={<Reports/>}/><Route path="/settings" element={<Settings/>}/><Route path="/topology" element={<Topology/>}/><Route path="/investigation" element={<Investigation/>}/><Route path="/osint" element={<OSINT/>}/><Route path="/audit" element={<AuditLogs/>}/><Route path="/team" element={<Team/>}/><Route path="/terminal" element={<Terminal/>}/><Route path="/netwatch" element={<NetWatch/>}/><Route path="/system-status" element={<SystemStatus/>}/><Route path="*" element={<Navigate to="/dashboard" replace/>}/></Routes></div></main><CommandPalette/><KeyboardShortcuts/></div>}
export default function App(){const location=useLocation();if(location.pathname==='/login'){if(getSession())return <Navigate to="/dashboard" replace/>;return <Routes><Route path="/login" element={<Login/>}/></Routes>}return <Protected/>}
