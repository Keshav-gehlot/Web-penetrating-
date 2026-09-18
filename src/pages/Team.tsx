import React, { useEffect, useMemo, useState } from 'react';
import { Copy, Mail, RefreshCw, Shield, Trash2, Check, LockKeyhole, Users, ChevronDown } from 'lucide-react';
import { authHeaders } from '../lib/auth';
import { useRBAC } from '../lib/RBACProvider';
import type { Permission, Role } from '../lib/rbac';

const API = (import.meta.env.VITE_PHANTOM_API_URL ?? 'http://localhost:8000').replace(/\/$/, '');
const ROLES: Role[] = ['owner', 'admin', 'security_lead', 'analyst', 'developer', 'viewer'];
const ROLE_LABEL: Record<Role, string> = {
  owner: 'Owner', admin: 'Admin', security_lead: 'Security Lead',
  analyst: 'Analyst', developer: 'Developer', viewer: 'Viewer',
};

type Member = { id: string; email: string; name: string; role: Role; active: boolean };

export default function Team() {
  const { profile, can, canRole, refresh: refreshRBAC } = useRBAC();
  const [members, setMembers] = useState<Member[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<'members' | 'permissions'>('members');
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState<Role>('analyst');
  const [invite, setInvite] = useState('');
  const [error, setError] = useState('');
  const [busyMember, setBusyMember] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API}/api/v1/workspaces/current/members`, { headers: authHeaders() });
      if (!response.ok) throw new Error(await response.text());
      setMembers(await response.json() as Member[]);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to load members');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  const ownerCount = useMemo(() => members.filter(member => member.role === 'owner' && member.active).length, [members]);

  async function add() {
    setError('');
    setInvite('');
    try {
      const response = await fetch(`${API}/api/v1/workspaces/current/invitations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ email, name, role }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || JSON.stringify(data));
      setEmail('');
      setName('');
      setInvite(data.invitation_token || '');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to create invitation');
    }
  }

  async function changeRole(member: Member, nextRole: Role) {
    if (nextRole === member.role) return;
    setBusyMember(member.id);
    setError('');
    try {
      const response = await fetch(`${API}/api/v1/workspaces/current/members/${encodeURIComponent(member.id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ role: nextRole }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || JSON.stringify(data));
      await load();
      await refreshRBAC();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to change role');
    } finally {
      setBusyMember(null);
    }
  }

  async function remove(member: Member) {
    if (member.role === 'owner' && ownerCount <= 1) {
      setError('The workspace must retain at least one owner.');
      return;
    }
    if (!confirm(`Remove ${member.name} from this workspace?`)) return;
    setBusyMember(member.id);
    setError('');
    try {
      const response = await fetch(`${API}/api/v1/workspaces/current/members/${encodeURIComponent(member.id)}`, {
        method: 'DELETE', headers: authHeaders(),
      });
      if (!response.ok) throw new Error(await response.text());
      await load();
      await refreshRBAC();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to remove member');
    } finally {
      setBusyMember(null);
    }
  }

  if (!can('users:manage')) {
    return <div className="h-full flex items-center justify-center text-sm text-phantom-text-secondary">You do not have permission to manage workspace members.</div>;
  }

  return (
    <div className="min-h-full bg-phantom-bg p-6 lg:p-8">
      <div className="max-w-6xl mx-auto">
        <header className="flex flex-wrap items-end justify-between gap-4 mb-6">
          <div>
            <div className="text-xs font-mono uppercase tracking-widest text-phantom-cyan mb-2">Workspace governance</div>
            <h1 className="text-2xl font-semibold tracking-tight">Team & Roles</h1>
            <p className="text-sm text-phantom-text-secondary mt-2">Manage membership and roles. The API remains authoritative for every authorization decision.</p>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1.5 rounded-lg border border-phantom-border bg-phantom-surface text-[10px] uppercase tracking-wider">
              Current role · {ROLE_LABEL[profile?.role ?? 'viewer']}
            </span>
            <button onClick={() => void load()} className="h-9 px-3 rounded-lg border border-phantom-border text-xs flex items-center gap-2"><RefreshCw size={13}/>Refresh</button>
          </div>
        </header>

        <div className="flex items-center gap-1 border-b border-phantom-border mb-5">
          <button onClick={() => setTab('members')} className={`px-3 py-2.5 text-xs font-medium border-b-2 ${tab === 'members' ? 'border-phantom-cyan text-phantom-text-primary' : 'border-transparent text-phantom-text-tertiary'}`}><Users size={13} className="inline mr-1.5"/>Members</button>
          <button onClick={() => setTab('permissions')} className={`px-3 py-2.5 text-xs font-medium border-b-2 ${tab === 'permissions' ? 'border-phantom-cyan text-phantom-text-primary' : 'border-transparent text-phantom-text-tertiary'}`}><LockKeyhole size={13} className="inline mr-1.5"/>Permission matrix</button>
        </div>

        {error && <div className="mb-5 rounded-lg border border-phantom-coral/30 bg-phantom-coral/10 px-3 py-2 text-xs text-phantom-coral whitespace-pre-wrap">{error}</div>}

        {tab === 'members' ? (
          <div className="grid lg:grid-cols-[360px_1fr] gap-5">
            <section className="border border-phantom-border bg-phantom-surface rounded-xl p-5 h-fit">
              <div className="flex items-center gap-2 text-sm font-semibold mb-4"><Mail size={16} className="text-phantom-cyan"/>Invite member</div>
              <div className="space-y-3">
                <input value={name} onChange={e => setName(e.target.value)} placeholder="Display name" className="w-full h-10 rounded-lg border border-phantom-border bg-phantom-bg px-3 text-xs outline-none"/>
                <input value={email} onChange={e => setEmail(e.target.value)} placeholder="Email" type="email" className="w-full h-10 rounded-lg border border-phantom-border bg-phantom-bg px-3 text-xs outline-none"/>
                <RoleSelect value={role} onChange={setRole} canRole={canRole}/>
                <button onClick={() => void add()} disabled={!email || !name || !canRole(role)} className="w-full h-10 rounded-lg bg-phantom-text-primary text-black text-xs font-semibold disabled:opacity-40">Create invitation</button>
              </div>
              {invite && <div className="mt-4 rounded-lg border border-phantom-cyan/30 bg-phantom-cyan/5 p-3">
                <div className="text-[10px] uppercase tracking-wider text-phantom-cyan">Development invitation token</div>
                <div className="mt-2 text-[11px] font-mono break-all">{invite}</div>
                <button onClick={() => void navigator.clipboard?.writeText(invite)} className="mt-2 text-[11px] flex items-center gap-1 text-phantom-text-secondary"><Copy size={12}/>Copy token</button>
              </div>}
              <div className="mt-4 text-[10px] leading-4 text-phantom-text-tertiary">Role assignment is constrained by the server-side role hierarchy. An administrator cannot grant a role above its own privilege level.</div>
            </section>

            <section className="border border-phantom-border bg-phantom-surface rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-phantom-border text-xs font-semibold uppercase tracking-wider text-phantom-text-tertiary">Members · {members.length} · owners {ownerCount}</div>
              {loading ? <div className="p-10 text-center text-sm text-phantom-text-tertiary">Loading…</div> : members.map(member => {
                const editable = canRole(member.role);
                const isLastOwner = member.role === 'owner' && ownerCount <= 1;
                return <div key={member.id} className="px-4 py-3 border-b last:border-0 border-phantom-border flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg border border-phantom-border bg-phantom-bg flex items-center justify-center"><Shield size={15} className="text-phantom-cyan"/></div>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium truncate">{member.name}{member.id === profile?.user_id ? ' · you' : ''}</div>
                    <div className="text-[11px] text-phantom-text-tertiary font-mono truncate">{member.email}</div>
                  </div>
                  <select value={member.role} disabled={!editable || busyMember === member.id} onChange={e => void changeRole(member, e.target.value as Role)} className="h-8 rounded-lg border border-phantom-border bg-phantom-bg px-2 text-[10px] capitalize disabled:opacity-40">
                    {ROLES.filter(canRole).map(candidate => <option key={candidate} value={candidate}>{ROLE_LABEL[candidate]}</option>)}
                  </select>
                  {busyMember === member.id && <span className="text-[10px] text-phantom-text-tertiary">Saving…</span>}
                  <span className={`text-[10px] ${member.active ? 'text-phantom-cyan' : 'text-phantom-coral'}`}>{member.active ? 'ACTIVE' : 'DISABLED'}</span>
                  <button onClick={() => void remove(member)} disabled={!editable || isLastOwner || busyMember === member.id} title={isLastOwner ? 'The workspace must retain at least one owner' : editable ? 'Remove member' : 'Insufficient privilege'} className="p-2 rounded hover:bg-phantom-panel text-phantom-text-tertiary hover:text-phantom-coral disabled:opacity-30 disabled:hover:text-phantom-text-tertiary"><Trash2 size={14}/></button>
                </div>;
              })}
            </section>
          </div>
        ) : <PermissionMatrix profile={profile} />}
      </div>
    </div>
  );
}

function RoleSelect({ value, onChange, canRole }: { value: Role; onChange: (role: Role) => void; canRole: (role: Role) => boolean }) {
  return <div className="relative"><select value={value} onChange={e => onChange(e.target.value as Role)} className="w-full h-10 rounded-lg border border-phantom-border bg-phantom-bg px-3 text-xs capitalize appearance-none">{ROLES.filter(canRole).map(role => <option key={role} value={role}>{ROLE_LABEL[role]}</option>)}</select><ChevronDown size={14} className="absolute right-3 top-3 pointer-events-none text-phantom-text-tertiary"/></div>;
}

function PermissionMatrix({ profile }: { profile: ReturnType<typeof useRBAC>['profile'] }) {
  if (!profile) return null;
  return <section className="border border-phantom-border bg-phantom-surface rounded-xl overflow-hidden">
    <div className="px-4 py-3 border-b border-phantom-border">
      <div className="text-sm font-semibold">Effective permission matrix</div>
      <div className="text-[11px] text-phantom-text-tertiary mt-1">Derived from the backend RBAC policy returned by <span className="font-mono">/auth/me</span>.</div>
    </div>
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[11px]">
        <thead><tr className="border-b border-phantom-border">{<th className="px-4 py-3 font-medium text-phantom-text-tertiary">Permission</th>}{ROLES.map(role => <th key={role} className="px-3 py-3 font-medium text-phantom-text-tertiary whitespace-nowrap">{ROLE_LABEL[role]}</th>)}</tr></thead>
        <tbody>{profile.all_permissions.map(permission => <tr key={permission} className="border-b border-phantom-border/70 last:border-0">
          <td className="px-4 py-2.5 font-mono text-phantom-text-secondary">{permission}</td>
          {ROLES.map(role => {
            const allowed = profile.permission_matrix[role]?.includes(permission);
            return <td key={role} className="px-3 py-2.5">{allowed ? <Check size={13} className="text-phantom-cyan"/> : <span className="text-phantom-text-tertiary">—</span>}</td>;
          })}
        </tr>)}</tbody>
      </table>
    </div>
  </section>;
}
