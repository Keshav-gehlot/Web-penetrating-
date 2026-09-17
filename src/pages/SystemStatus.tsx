import React, { useCallback, useEffect, useState } from 'react';
import { Activity, Database, RefreshCw, Server, Wifi, AlertTriangle } from 'lucide-react';
import { authHeaders } from '../lib/auth';

const API = (import.meta.env.VITE_PHANTOM_API_URL ?? 'http://localhost:8000').replace(/\/$/, '');

type Status = {
  redis: { stream: string; queue_length: number; pending: number };
  workers: { id: string; status: string; heartbeat: string }[];
  scans: { active: number; queued: number };
};

type OperationalEvent = {
  id: string;
  event_type: string;
  severity: string;
  message: string;
  scan_id: string | null;
  created_at: string | null;
};

export default function SystemStatus() {
  const [data, setData] = useState<Status | null>(null);
  const [events, setEvents] = useState<OperationalEvent[]>([]);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const headers = authHeaders();
      const [statusResponse, eventsResponse] = await Promise.all([
        fetch(`${API}/api/v1/system/status`, { headers }),
        fetch(`${API}/api/v1/operations/events?limit=30`, { headers }),
      ]);
      if (!statusResponse.ok) throw new Error('Unable to read system status');
      if (!eventsResponse.ok) throw new Error('Unable to read operational events');
      setData(await statusResponse.json());
      setEvents(await eventsResponse.json());
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to read system status');
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(timer);
  }, [load]);

  return (
    <div className="min-h-full bg-phantom-bg p-6 lg:p-8">
      <div className="mx-auto max-w-[1200px]">
        <div className="mb-7 flex items-end justify-between">
          <div>
            <div className="mb-2 font-mono text-xs uppercase tracking-[.18em] text-phantom-cyan">Operations</div>
            <h1 className="text-2xl font-semibold">System Status</h1>
            <p className="mt-2 text-sm text-phantom-text-secondary">Worker, queue, scan execution and operational event health.</p>
          </div>
          <button onClick={() => void load()} className="flex h-9 items-center gap-2 rounded-lg border border-phantom-border px-3 text-xs">
            <RefreshCw size={13} /> Refresh
          </button>
        </div>

        {error && <div className="mb-5 rounded-lg border border-phantom-coral/30 p-3 text-xs text-phantom-coral">{error}</div>}

        <div className="grid gap-4 md:grid-cols-3">
          <Card icon={<Server size={16} />} title="Workers">
            <div className="font-mono text-2xl font-semibold">{data?.workers.length ?? 0}</div>
            <div className="mt-2 text-xs text-phantom-text-tertiary">
              {data?.workers.map((worker) => <div key={worker.id} className="flex justify-between py-1"><span className="truncate">{worker.id}</span><span className="text-phantom-cyan">{worker.status}</span></div>)}
            </div>
          </Card>
          <Card icon={<Activity size={16} />} title="Scan execution">
            <div className="flex gap-7"><div><div className="font-mono text-2xl font-semibold">{data?.scans.active ?? 0}</div><div className="text-[10px] uppercase text-phantom-text-tertiary">Active</div></div><div><div className="font-mono text-2xl font-semibold">{data?.scans.queued ?? 0}</div><div className="text-[10px] uppercase text-phantom-text-tertiary">Queued</div></div></div>
          </Card>
          <Card icon={<Database size={16} />} title="Redis queue">
            <div className="font-mono text-2xl font-semibold">{data?.redis.pending ?? 0}</div>
            <div className="mt-2 text-xs text-phantom-text-tertiary">Pending consumer-group messages</div>
            <div className="mt-3 font-mono text-[10px] text-phantom-text-tertiary">{data?.redis.stream ?? '—'}</div>
          </Card>
        </div>

        <div className="mt-5 rounded-xl border border-phantom-border bg-phantom-surface p-5">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-phantom-text-tertiary"><Wifi size={14} /> Execution posture</div>
          <div className="mt-5 grid gap-4 text-xs md:grid-cols-3">
            <div><span className="text-phantom-text-tertiary">Queue depth</span><div className="mt-1 font-mono">{data?.redis.queue_length ?? 0}</div></div>
            <div><span className="text-phantom-text-tertiary">Worker lease model</span><div className="mt-1">Database + Redis lease</div></div>
            <div><span className="text-phantom-text-tertiary">Telemetry refresh</span><div className="mt-1">5 seconds</div></div>
          </div>
        </div>

        <div className="mt-5 rounded-xl border border-phantom-border bg-phantom-surface p-5">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-phantom-text-tertiary"><AlertTriangle size={14} /> Recent operational events</div>
          <div className="mt-4 divide-y divide-phantom-border/70">
            {events.length === 0 ? <div className="py-6 text-xs text-phantom-text-tertiary">No operational events recorded.</div> : events.map((event) => (
              <div key={event.id} className="grid gap-2 py-3 md:grid-cols-[120px_140px_1fr_160px] md:items-center">
                <span className="font-mono text-[10px] text-phantom-text-tertiary">{event.created_at ? new Date(event.created_at).toLocaleTimeString() : '—'}</span>
                <span className="font-mono text-[10px] uppercase text-phantom-cyan">{event.event_type}</span>
                <span className="text-xs text-phantom-text-secondary">{event.message}</span>
                <span className="truncate font-mono text-[10px] text-phantom-text-tertiary">{event.scan_id ?? 'system'}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function Card({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return <section className="rounded-xl border border-phantom-border bg-phantom-surface p-5"><div className="mb-5 flex items-center gap-2 text-xs uppercase tracking-wider text-phantom-text-tertiary">{icon}{title}</div>{children}</section>;
}
