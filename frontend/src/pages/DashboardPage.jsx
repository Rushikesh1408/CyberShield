import { useEffect, useMemo, useState } from 'react';

import ActivityChart from '../components/ActivityChart';
import AlertsPanel from '../components/AlertsPanel';
import FingerprintPanel from '../components/FingerprintPanel';
import LogsTimeline from '../components/LogsTimeline';
import StatusCard from '../components/StatusCard';

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:5000';

const initialSnapshot = {
  status: 'SAFE',
  monitor_paths: [],
  monitoring_message: 'Monitoring: Protected System Directories (Auto-configured)',
  metrics: {
    files_per_second: 0,
    modifications: 0,
    accesses: 0,
    cpu_percent: 0,
    status: 'SAFE',
  },
  alerts: [],
  logs: [],
  fingerprints: [],
};

function timeLabel(timestamp) {
  if (!timestamp) {
    return '--:--:--';
  }

  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return timestamp.slice(11, 19);
  }

  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

async function fetchJson(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });

  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }

  return response.json();
}

export default function DashboardPage() {
  const [snapshot, setSnapshot] = useState(initialSnapshot);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const loadSnapshot = async () => {
    try {
      const [statusData, alertsData, logsData, fingerprintsData, metricsData] =
        await Promise.all([
          fetchJson('/api/status'),
          fetchJson('/api/alerts'),
          fetchJson('/api/logs'),
          fetchJson('/api/fingerprints'),
          fetchJson('/api/metrics'),
        ]);

      setSnapshot({
        status: statusData.status,
        monitor_paths: statusData.monitor_paths ?? [],
        monitoring_message:
          statusData.monitoring_message ??
          'Monitoring: Protected System Directories (Auto-configured)',
        metrics: metricsData.metrics ?? initialSnapshot.metrics,
        alerts: alertsData.alerts ?? [],
        logs: logsData.logs ?? [],
        fingerprints: fingerprintsData.fingerprints ?? [],
      });

      const graphHistory = (metricsData.history ?? []).map((entry) => ({
        label: timeLabel(entry.timestamp),
        files_per_second: Number(entry.files_per_second ?? 0),
      }));
      setHistory(graphHistory);
      setError('');
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSnapshot();
    const interval = window.setInterval(loadSnapshot, 2000);
    return () => window.clearInterval(interval);
  }, []);

  const isUnderAttack = snapshot.status === 'UNDER_ATTACK';
  const chartData = useMemo(() => history.slice(-20), [history]);

  const handleStart = async () => {
    setBusy(true);
    try {
      await fetchJson('/api/start', {
        method: 'POST',
      });
      await loadSnapshot();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  };

  const handleStop = async () => {
    setBusy(true);
    try {
      await fetchJson('/api/stop', { method: 'POST' });
      await loadSnapshot();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="min-h-screen bg-transparent px-4 py-6 text-slate-100 sm:px-6 lg:px-10">
      <div className="mx-auto max-w-7xl space-y-6">
        <section className="overflow-hidden rounded-[2rem] border border-slate-800/80 bg-slate-950/80 shadow-2xl shadow-slate-950/50 backdrop-blur-xl">
          <div className="grid gap-6 px-6 py-6 lg:grid-cols-[1.4fr_0.8fr] lg:px-8 lg:py-8">
            <div>
              <div className="inline-flex items-center rounded-full border border-slate-700 bg-slate-900/80 px-4 py-1 text-xs uppercase tracking-[0.32em] text-sky-300">
                CyberShield AI
              </div>
              <h1 className="mt-5 max-w-3xl text-4xl font-semibold tracking-tight text-white sm:text-5xl">
                Real-Time Ransomware Defense & Zero Data Loss System
              </h1>
              <p className="mt-4 max-w-2xl text-base leading-7 text-slate-300">
                Automatically monitor protected system directories, detect ransomware-like
                bursts, kill suspicious processes, restore files from versioned backups, and
                store reusable attack fingerprints.
              </p>
              <div className="mt-6 flex flex-wrap items-center gap-3">
                <span
                  className={`rounded-full border px-4 py-2 text-sm font-medium ${
                    isUnderAttack
                      ? 'border-rose-400/30 bg-rose-500/10 text-rose-100'
                      : 'border-emerald-400/30 bg-emerald-500/10 text-emerald-100'
                  }`}
                >
                  {snapshot.status}
                </span>
                <span className="rounded-full border border-slate-700 bg-slate-900/70 px-4 py-2 text-sm text-slate-300">
                  Monitor: {snapshot.metrics.status}
                </span>
                {loading ? (
                  <span className="text-sm text-slate-400">Loading live snapshot...</span>
                ) : null}
              </div>

              <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <StatusCard
                  title="File Rate"
                  value={`${snapshot.metrics.files_per_second.toFixed(1)} /s`}
                  caption="Rolling files per second"
                  accent="blue"
                />
                <StatusCard
                  title="CPU"
                  value={`${snapshot.metrics.cpu_percent.toFixed(0)}%`}
                  caption="Host CPU spike check"
                  accent={isUnderAttack ? 'rose' : 'green'}
                />
                <StatusCard
                  title="Modifications"
                  value={snapshot.metrics.modifications}
                  caption="Recent file write count"
                  accent="amber"
                />
                <StatusCard
                  title="Alerts"
                  value={snapshot.alerts.length}
                  caption="Stored timeline entries"
                  accent={isUnderAttack ? 'rose' : 'blue'}
                />
              </div>
            </div>

            <div className="rounded-[1.75rem] border border-slate-800 bg-slate-900/70 p-5">
              <div className="text-sm uppercase tracking-[0.26em] text-slate-400">Demo Controls</div>
              <div className="mt-3 text-2xl font-semibold text-white">Auto protection loop</div>
              <p className="mt-2 text-sm leading-6 text-slate-300">
                The engine automatically protects configured system directories. Launch a
                ransomware simulation to see early detection, process kill, and recovery.
              </p>
              <div className="mt-5 rounded-2xl border border-slate-700 bg-slate-950/70 px-4 py-3 text-sm text-slate-300">
                {snapshot.monitoring_message}
              </div>
              <div className="mt-4 grid grid-cols-2 gap-3">
                <button
                  type="button"
                  disabled={busy}
                  onClick={handleStart}
                  className="rounded-2xl bg-sky-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  Start Monitoring
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={handleStop}
                  className="rounded-2xl border border-slate-700 bg-slate-950/70 px-4 py-3 text-sm font-semibold text-white transition hover:border-slate-500 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  Stop Monitoring
                </button>
              </div>
              <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/80 p-4 text-sm text-slate-300">
                <div className="flex items-center justify-between gap-3">
                  <span>Status</span>
                  <span className={isUnderAttack ? 'text-rose-300' : 'text-emerald-300'}>
                    {snapshot.status}
                  </span>
                </div>
                <div className="mt-2 flex items-center justify-between gap-3">
                  <span>Scope</span>
                  <span className="max-w-[16rem] truncate text-slate-400">
                    {snapshot.monitor_paths.length > 0
                      ? `${snapshot.monitor_paths.length} protected directories`
                      : 'Protected folder fallback'}
                  </span>
                </div>
                <div className="mt-3 rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-xs text-slate-400">
                  {snapshot.monitor_paths.length > 0
                    ? snapshot.monitor_paths.join(' | ')
                    : 'No system directories found. Using protected_folder fallback.'}
                </div>
              </div>
              {error ? (
                <div className="mt-4 rounded-2xl border border-rose-400/30 bg-rose-500/10 p-4 text-sm text-rose-100">
                  {error}
                </div>
              ) : null}
            </div>
          </div>
        </section>

        <section className="grid gap-6 xl:grid-cols-[1.4fr_0.9fr]">
          <ActivityChart data={chartData} />
          <AlertsPanel alerts={snapshot.alerts} />
        </section>

        <section className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
          <LogsTimeline logs={snapshot.logs} />
          <FingerprintPanel fingerprints={snapshot.fingerprints} />
        </section>
      </div>
    </main>
  );
}
