import { useEffect, useMemo, useState } from 'react';

import ActivityChart from '../components/ActivityChart';
import AlertsPanel from '../components/AlertsPanel';
import BackupRecoveryPanel from '../components/BackupRecoveryPanel';
import EmergencyPanel from '../components/EmergencyPanel';
import FingerprintPanel from '../components/FingerprintPanel';
import LogsTimeline from '../components/LogsTimeline';
import StatusCard from '../components/StatusCard';

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:5000';

const initialSnapshot = {
  status: 'SAFE',
  is_monitoring: false,
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

async function fetchJson(path, options = {}, timeoutMs = 8000) {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);

  const method = (options.method ?? 'GET').toUpperCase();
  const headers = { ...(options.headers ?? {}) };
  if (method !== 'GET' && method !== 'HEAD' && options.body !== undefined) {
    headers['Content-Type'] = headers['Content-Type'] ?? 'application/json';
  }

  const response = await fetch(`${API_BASE}${path}`, {
    headers,
    ...options,
    signal: controller.signal,
  });

  window.clearTimeout(timeoutId);

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
  const [clearingLogs, setClearingLogs] = useState(false);
  const [isRunningBackup, setIsRunningBackup] = useState(false);
  const [isRecovering, setIsRecovering] = useState(false);
  const [backupStatus, setBackupStatus] = useState({
    status: 'Inactive',
    files_secured: 0,
    backup_versions: 0,
    last_backup_time: null,
    recent_files: [],
    backup_root: '',
  });
  const [backupMessage, setBackupMessage] = useState('');
  const [emergencyContact, setEmergencyContact] = useState('');
  const [isSavingContact, setIsSavingContact] = useState(false);
  const [isDownloadingReport, setIsDownloadingReport] = useState(false);
  const [emergencyMessage, setEmergencyMessage] = useState('');
  const [error, setError] = useState('');

  const loadEmergencyContact = async () => {
    try {
      const data = await fetchJson('/api/emergency/contact', {}, 5000);
      setEmergencyContact(String(data.contact ?? ''));
    } catch {
      // Keep current value to avoid breaking main dashboard polling.
    }
  };

  const loadBackupStatus = async () => {
    try {
      const backupData = await fetchJson('/api/backup/status', {}, 5000);
      setBackupStatus({
        status: backupData.status ?? 'Inactive',
        files_secured: Number(backupData.files_secured ?? 0),
        backup_versions: Number(backupData.backup_versions ?? 0),
        last_backup_time: backupData.last_backup_time ?? null,
        recent_files: Array.isArray(backupData.recent_files) ? backupData.recent_files : [],
        backup_root: backupData.backup_root ?? '',
      });
    } catch {
      // Keep existing backup status to avoid blocking realtime metrics UI.
    }
  };

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
        is_monitoring: Boolean(statusData.is_monitoring),
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
      if (requestError.name === 'AbortError') {
        setError('Request timeout. Reconnecting to backend...');
      } else {
        setError(requestError.message);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSnapshot();
    loadBackupStatus();
    loadEmergencyContact();

    const snapshotInterval = window.setInterval(loadSnapshot, 2000);
    const backupInterval = window.setInterval(loadBackupStatus, 10000);

    return () => {
      window.clearInterval(snapshotInterval);
      window.clearInterval(backupInterval);
    };
  }, []);

  const isUnderAttack = snapshot.status === 'UNDER_ATTACK';
  const chartData = useMemo(() => history.slice(-20), [history]);

  const handleStart = async () => {
    setBusy(true);
    try {
      await fetchJson('/api/start', {
        method: 'POST',
      }, 20000);
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
      await fetchJson('/api/stop', { method: 'POST' }, 20000);
      await loadSnapshot();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  };

  const handleClearLogs = async () => {
    setClearingLogs(true);
    try {
      await fetchJson('/api/logs/clear', { method: 'POST' });
      setSnapshot((current) => ({ ...current, logs: [] }));
      await loadSnapshot();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setClearingLogs(false);
    }
  };

  const handleRunBackup = async () => {
    setIsRunningBackup(true);
    try {
      const response = await fetchJson('/api/backup/run', { method: 'POST' });
      setBackupMessage(`Backup completed. Created versions: ${response.created ?? 0}`);
      await loadSnapshot();
      await loadBackupStatus();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setIsRunningBackup(false);
    }
  };

  const handleRecoverFile = async (filePath) => {
    setIsRecovering(true);
    try {
      await fetchJson('/api/backup/recover', {
        method: 'POST',
        body: JSON.stringify({ file_path: filePath }),
      });
      setBackupMessage(`Recovered file: ${filePath}`);
      await loadSnapshot();
      await loadBackupStatus();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setIsRecovering(false);
    }
  };

  const handleSaveEmergencyContact = async () => {
    const phone = emergencyContact.trim();
    if (!phone) {
      setEmergencyMessage('Please enter a phone number before saving.');
      return;
    }

    setIsSavingContact(true);
    try {
      const response = await fetchJson('/api/emergency/contact', {
        method: 'POST',
        body: JSON.stringify({ phone }),
      });
      setEmergencyContact(String(response.contact ?? phone));
      setEmergencyMessage('Emergency contact saved successfully.');
      setError('');
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setIsSavingContact(false);
    }
  };

  const handleDownloadAttackReport = async () => {
    setIsDownloadingReport(true);
    try {
      const controller = new AbortController();
      const timeoutId = window.setTimeout(() => controller.abort(), 8000);
      const response = await fetch(`${API_BASE}/api/report/download`, {
        method: 'GET',
        signal: controller.signal,
      });
      window.clearTimeout(timeoutId);

      if (!response.ok) {
        let message = `Request failed: ${response.status}`;
        try {
          const payload = await response.json();
          message = payload.message ? String(payload.message) : message;
        } catch {
          // Ignore JSON parsing errors for non-JSON responses.
        }
        throw new Error(message);
      }

      const blob = await response.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = downloadUrl;
      anchor.download = 'attack_report.txt';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(downloadUrl);
      setEmergencyMessage('Attack report downloaded.');
      setError('');
    } catch (requestError) {
      const rawMessage = String(requestError.message ?? 'Failed to download report.');
      if (rawMessage.toLowerCase().includes('report_not_found')) {
        setEmergencyMessage('No attack report available yet. Trigger a simulation first.');
      }
      setError(rawMessage);
    } finally {
      setIsDownloadingReport(false);
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
                  Monitor: {snapshot.is_monitoring ? 'Active' : 'Inactive'}
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
                  value={`${snapshot.metrics.cpu_percent.toFixed(1)}%`}
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
          <LogsTimeline
            logs={snapshot.logs}
            onClearLogs={handleClearLogs}
            isClearingLogs={clearingLogs}
          />
          <FingerprintPanel fingerprints={snapshot.fingerprints} />
        </section>

        <BackupRecoveryPanel
          backupStatus={backupStatus}
          onRunBackup={handleRunBackup}
          onRecoverFile={handleRecoverFile}
          isRunningBackup={isRunningBackup}
          isRecovering={isRecovering}
          message={backupMessage}
        />

        <EmergencyPanel
          emergencyContact={emergencyContact}
          onEmergencyContactChange={setEmergencyContact}
          onSaveContact={handleSaveEmergencyContact}
          onDownloadReport={handleDownloadAttackReport}
          isSavingContact={isSavingContact}
          isDownloadingReport={isDownloadingReport}
          message={emergencyMessage}
        />
      </div>
    </main>
  );
}
