import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { getSession } from './auth';
import { hasPermission as hasCachedPermission, loadRBAC, type Permission, type RBACProfile, type Role } from './rbac';

type RBACContextValue = {
  profile: RBACProfile | null;
  loading: boolean;
  refresh: () => Promise<void>;
  can: (permission: Permission) => boolean;
  canRole: (role: Role) => boolean;
};

const RBACContext = createContext<RBACContextValue | null>(null);

export function RBACProvider({ children }: { children: React.ReactNode }) {
  const [profile, setProfile] = useState<RBACProfile | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    if (!getSession()) {
      setProfile(null);
      setLoading(false);
      return;
    }
    const next = await loadRBAC();
    setProfile(next);
    setLoading(false);
  };

  useEffect(() => { void refresh(); }, []);

  const value = useMemo<RBACContextValue>(() => ({
    profile,
    loading,
    refresh,
    can: (permission) => Boolean(profile && hasCachedPermission(permission)),
    canRole: (role) => {
      if (!profile) return false;
      if (profile.role === 'owner') return true;
      const levels: Record<Role, number> = { owner: 6, admin: 5, security_lead: 4, analyst: 3, developer: 2, viewer: 1 };
      return levels[role] <= levels[profile.role];
    },
  }), [profile, loading]);

  return <RBACContext.Provider value={value}>{children}</RBACContext.Provider>;
}

export function useRBAC(): RBACContextValue {
  const value = useContext(RBACContext);
  if (!value) throw new Error('useRBAC must be used inside RBACProvider');
  return value;
}
