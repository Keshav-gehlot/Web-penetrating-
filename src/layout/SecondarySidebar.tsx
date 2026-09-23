import React from 'react';
import { useLocation } from 'react-router-dom';

const SECTIONS: Record<string, { title: string; description: string }> = {
  dashboard: { title: 'Overview', description: 'Workspace posture and operational activity.' },
  assets: { title: 'Assets', description: 'Registered workspace targets and observed risk.' },
  scope: { title: 'Assessment Governance', description: 'Authorization boundaries and scan limits.' },
  vulnerabilities: { title: 'Vulnerabilities', description: 'Findings, triage, remediation, and verification.' },
  scans: { title: 'Scan Management', description: 'Launch and review bounded assessments.' },
  schedules: { title: 'Schedules', description: 'Manage recurring assessment dispatch.' },
  reports: { title: 'Reports', description: 'Generate reports from persisted assessment data.' },
  settings: { title: 'Settings', description: 'Account and workspace configuration.' },
  topology: { title: 'Asset Topology', description: 'Data-driven workspace asset relationships.' },
  investigation: { title: 'Investigation', description: 'Evidence, notes, timelines, and validation context.' },
  osint: { title: 'OSINT', description: 'Source and intelligence discovery.' },
  audit: { title: 'Audit Logs', description: 'Security-relevant workspace activity.' },
  team: { title: 'Team & Roles', description: 'Workspace membership and access control.' },
  terminal: { title: 'System Terminal', description: 'Queue, worker, and execution health.' },
  netwatch: { title: 'Net-Watch', description: 'Authenticated endpoint network observability.' },
  'system-status': { title: 'System Status', description: 'Current application dependency and worker health.' },
};

export function SecondarySidebar() {
  const { pathname } = useLocation();
  const key = pathname.split('/')[1] || 'dashboard';
  const section = SECTIONS[key] ?? { title: 'PHANTOM', description: 'Security operations console.' };

  return (
    <aside className="w-[240px] h-full bg-phantom-bg flex-shrink-0 border-r border-transparent hidden md:flex">
      <div className="px-5 py-6">
        <div className="text-sm font-semibold">{section.title}</div>
        <p className="mt-2 text-xs leading-5 text-phantom-text-tertiary">{section.description}</p>
      </div>
    </aside>
  );
}
