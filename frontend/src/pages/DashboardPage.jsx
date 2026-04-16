import { useEffect, useMemo, useState } from 'react';

import ActivityChart from '../components/ActivityChart';
import AttackInsightsPanel from '../components/AttackInsightsPanel';
import AlertsPanel from '../components/AlertsPanel';
import BackupRecoveryPanel from '../components/BackupRecoveryPanel';
import EmergencyPanel from '../components/EmergencyPanel';
import FingerprintPanel from '../components/FingerprintPanel';
import LogsTimeline from '../components/LogsTimeline';
import StatusCard from '../components/StatusCard';
import SystemTimelinePanel from '../components/SystemTimelinePanel';
import InterventionPanel from '../components/InterventionPanel';

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:5000';

function joinApiUrl(path) {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const normalizedBase = String(API_BASE || '').replace(/\/$/, '');

  if (!normalizedBase) {
    return normalizedPath;
  }

  if (normalizedBase.endsWith('/api') && normalizedPath.startsWith('/api/')) {
    return `${normalizedBase}${normalizedPath.slice(4)}`;
  }

  return `${normalizedBase}${normalizedPath}`;
}

const initialSnapshot = {
  status: 'SAFE',
  confidence: 0,
  is_monitoring: false,
  monitor_paths: [],
  monitoring_message: 'Monitoring: Protected System Directories (Auto-configured)',
  core_pipeline: {
    is_running: false,
    network_mode: 'safe',
    threat: {
      score: 0,
      level: 'LOW',
      trigger_threshold: 70,
      metrics: {
        tracked_files: 0,
        dna_mismatch_count: 0,
      },
    },
  },
  metrics: {
    files_per_second: 0,
    modifications: 0,
    accesses: 0,
    cpu_percent: 0,
    cpu_percent_raw: 0,
    cpu_percent_sampled: 0,
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

  const response = await fetch(joinApiUrl(path), {
    headers,
    ...options,
    signal: controller.signal,
  });

  window.clearTimeout(timeoutId);

  if (!response.ok) {
    let message = `Request failed: ${response.status}`;
    try {
      const payload = await response.json();
      if (payload && typeof payload.message === 'string' && payload.message.trim()) {
        message = payload.message;
      }
    } catch {
      // Keep default error text when backend response is not JSON.
    }
    throw new Error(message);
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
  const [isRunningIntervention, setIsRunningIntervention] = useState(false);
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
  const [isSimulating, setIsSimulating] = useState(false);
  const [emergencyMessage, setEmergencyMessage] = useState('');
  const [interventionMessage, setInterventionMessage] = useState('');
  const [interventionResult, setInterventionResult] = useState(null);
  const [attackSummary, setAttackSummary] = useState({
    files_protected: 0,
    files_encrypted: 0,
    files_recovered: 0,
    threat_confidence: 0,
    honeytrap_triggers: 0,
  });
  const [fileStats, setFileStats] = useState({
    files_protected: 0,
    files_recovered: 0,
  });
  const [timeline, setTimeline] = useState([]);
  const [error, setError] = useState('');

  const loadSystemIntelligence = async () => {
    try {
      const [summaryResult, statsResult, timelineResult] = await Promise.allSettled([
        fetchJson('/api/attack/summary', {}, 6000),
        fetchJson('/api/file-stats', {}, 6000),
        fetchJson('/api/timeline', {}, 6000),
      ]);

      if (summaryResult.status === 'fulfilled') {
        const summaryData = summaryResult.value;
        setAttackSummary({
          files_protected: Number(summaryData.files_protected ?? 0),
          files_encrypted: Number(summaryData.files_encrypted ?? 0),
          files_recovered: Number(summaryData.files_recovered ?? 0),
          threat_confidence: Number(summaryData.threat_confidence ?? 0),
          honeytrap_triggers: Number(summaryData.honeytrap_triggers ?? 0),
        });
      }

      if (statsResult.status === 'fulfilled') {
        const statsData = statsResult.value;
        setFileStats({
          files_protected: Number(statsData.files_protected ?? 0),
          files_recovered: Number(statsData.files_recovered ?? 0),
        });
      }

      if (timelineResult.status === 'fulfilled') {
        const timelineData = timelineResult.value;
        setTimeline(Array.isArray(timelineData.timeline) ? timelineData.timeline : []);
      }
    } catch {
      // Keep the last successful intelligence snapshot if polling is interrupted.
    }
  };

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
    const [statusResult, alertsResult, logsResult, fingerprintsResult, metricsResult] =
      await Promise.allSettled([
        fetchJson('/api/status'),
        fetchJson('/api/alerts'),
        fetchJson('/api/logs'),
        fetchJson('/api/fingerprints'),
        fetchJson('/api/metrics'),
      ]);

    setSnapshot((current) => {
      const nextSnapshot = { ...current };

      if (statusResult.status === 'fulfilled') {
        const statusData = statusResult.value;
        nextSnapshot.status = statusData.status;
        nextSnapshot.confidence = Number(statusData.confidence ?? 0);
        nextSnapshot.is_monitoring = Boolean(statusData.is_monitoring);
        nextSnapshot.monitor_paths = statusData.monitor_paths ?? [];
        nextSnapshot.monitoring_message =
          statusData.monitoring_message ??
          'Monitoring: Protected System Directories (Auto-configured)';
        nextSnapshot.core_pipeline = statusData.core_pipeline ?? initialSnapshot.core_pipeline;
      }

      if (alertsResult.status === 'fulfilled') {
        nextSnapshot.alerts = alertsResult.value.alerts ?? [];
      }

      if (logsResult.status === 'fulfilled') {
        nextSnapshot.logs = logsResult.value.logs ?? [];
      }

      if (fingerprintsResult.status === 'fulfilled') {
        nextSnapshot.fingerprints = fingerprintsResult.value.fingerprints ?? [];
      }

      if (metricsResult.status === 'fulfilled') {
        nextSnapshot.metrics = metricsResult.value.metrics ?? initialSnapshot.metrics;
        const graphHistory = (metricsResult.value.history ?? []).map((entry) => ({
          // Keep chart responsive to both short bursts and sustained file churn.
          activity_signal: Math.max(
            Number(entry.files_per_second ?? 0),
            Number(entry.modifications ?? 0),
          ),
          label: timeLabel(entry.timestamp),
          files_per_second: Number(entry.files_per_second ?? 0),
        }));
        setHistory(graphHistory);
      }

      return nextSnapshot;
    });

    const requestErrors = [statusResult, alertsResult, logsResult, fingerprintsResult, metricsResult].filter(
      (result) => result.status === 'rejected',
    );

    if (requestErrors.length === 5) {
      const firstError = requestErrors[0].reason;
      if (firstError?.name === 'AbortError') {
        setError('Request timeout. Reconnecting to backend...');
      } else {
        setError(firstError?.message ?? 'Failed to refresh dashboard data.');
      }
    } else {
      setError('');
    }

    setLoading(false);
  };

  useEffect(() => {
    loadSnapshot();
    loadBackupStatus();
    loadEmergencyContact();
    loadSystemIntelligence();

    const snapshotInterval = window.setInterval(loadSnapshot, 2000);
    const backupInterval = window.setInterval(loadBackupStatus, 10000);
    const intelligenceInterval = window.setInterval(loadSystemIntelligence, 4000);

    return () => {
      window.clearInterval(snapshotInterval);
      window.clearInterval(backupInterval);
      window.clearInterval(intelligenceInterval);
    };
  }, []);

  const isUnderAttack = snapshot.status === 'UNDER_ATTACK';
  const toNumericValue = (value) => {
    const numericValue = Number(value);
    return Number.isNaN(numericValue) ? 0 : numericValue;
  };
  const cpuDisplayValue = Math.max(
    toNumericValue(snapshot.metrics.cpu_percent),
    toNumericValue(snapshot.metrics.cpu_percent_raw),
    toNumericValue(snapshot.metrics.cpu_percent_sampled),
  );
  const threatConfidence = Math.max(
    toNumericValue(snapshot.confidence),
    toNumericValue(snapshot.metrics.threat_confidence),
    toNumericValue(attackSummary.threat_confidence),
  );
  const pipelineState = snapshot.core_pipeline ?? initialSnapshot.core_pipeline;
  const pipelineThreat = pipelineState.threat ?? initialSnapshot.core_pipeline.threat;
  const pipelineThreatLevel = String(pipelineThreat.level ?? 'LOW').toUpperCase();
  const pipelineThreatScore = toNumericValue(pipelineThreat.score);
  const pipelineMode = String(pipelineState.network_mode ?? 'safe').toUpperCase();
  const trackedFiles = toNumericValue(pipelineThreat.metrics?.tracked_files);
  const dnaMismatchCount = toNumericValue(pipelineThreat.metrics?.dna_mismatch_count);
  const pipelineAccent =
    pipelineThreatLevel === 'HIGH'
      ? 'rose'
      : pipelineThreatLevel === 'MEDIUM'
        ? 'amber'
        : 'green';
  const chartData = useMemo(
    () => history.slice(-120).map((entry) => ({
      ...entry,
      files_per_second: Number(entry.activity_signal ?? entry.files_per_second ?? 0),
    })),
    [history],
  );

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

  const handleRunAttackSimulation = async () => {
    setIsSimulating(true);
    try {
      const response = await fetchJson(
        '/api/simulate/attack',
        {
          method: 'POST',
          body: JSON.stringify({ level: 'high', wait_timeout: 30 }),
        },
        45000,
      );

      const summary = response.attack_summary ?? {};
      const encrypted = Number(summary.files_encrypted ?? 0);
      const recovered = Number(summary.files_recovered ?? 0);
      const reportReady = Boolean(response.report_ready);

      setEmergencyMessage(
        reportReady
          ? `Simulation completed. Encrypted: ${encrypted}, Recovered: ${recovered}. Report generated.`
          : `Simulation completed. Encrypted: ${encrypted}, Recovered: ${recovered}. Report still pending.`,
      );
      setError('');
      await loadSnapshot();
      await loadBackupStatus();
      await loadSystemIntelligence();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleSafeIntervention = async () => {
    setIsRunningIntervention(true);
    try {
      const response = await fetchJson(
        '/api/intervention/handle',
        {
          method: 'POST',
          body: JSON.stringify({
            lookback_seconds: 5,
            cpu_threshold: 65,
            terminate_threshold: 60,
            recheck_delay_seconds: 1.5,
          }),
        },
        45000,
      );

      setInterventionResult({
        status: String(response.status ?? 'SAFE'),
        action_taken: Array.isArray(response.action_taken) ? response.action_taken : [],
        files_protected: Number(response.files_protected ?? 0),
        files_recovered: Number(response.files_recovered ?? 0),
        suspicious_processes: Array.isArray(response.suspicious_processes) ? response.suspicious_processes : [],
        confirmed_processes: Array.isArray(response.confirmed_processes) ? response.confirmed_processes : [],
      });

      const actionSummary = Array.isArray(response.action_taken) && response.action_taken.length > 0
        ? response.action_taken.join(', ')
        : 'no_actions_needed';
      setInterventionMessage(
        `Safe intervention completed with ${actionSummary}. Protected ${Number(response.files_protected ?? 0)} files and recovered ${Number(response.files_recovered ?? 0)} files.`,
      );
      setError('');
      await loadSnapshot();
      await loadBackupStatus();
      await loadSystemIntelligence();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setIsRunningIntervention(false);
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
      setBackupMessage(`Versioned snapshot completed. Created versions: ${response.created ?? 0}`);
      await loadSnapshot();
      await loadBackupStatus();
      await loadSystemIntelligence();
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
      setBackupMessage(`Automatic System Recovery restored: ${filePath}`);
      await loadSnapshot();
      await loadBackupStatus();
      await loadSystemIntelligence();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setIsRecovering(false);
    }
  };

  const handleSaveEmergencyContact = async () => {
    const email = emergencyContact.trim();
    if (!email) {
      setEmergencyMessage('Please enter an email address before saving.');
      return;
    }

    setIsSavingContact(true);
    try {
      const response = await fetchJson('/api/emergency/contact', {
        method: 'POST',
        body: JSON.stringify({ email }),
      });
      setEmergencyContact(String(response.contact ?? email));
      setEmergencyMessage('Emergency email contact saved successfully.');
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
      const response = await fetch(joinApiUrl('/api/report/download'), {
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
      setEmergencyMessage('CyberShield attack report downloaded.');
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
                CyberShield
              </div>
              <h1 className="mt-5 max-w-3xl text-4xl font-semibold tracking-tight text-white sm:text-5xl">
                CyberShield - Ransomware Defense System
              </h1>
              <p className="mt-4 max-w-2xl text-base leading-7 text-slate-300">
                Early Threat Detection, Active Threat Neutralization, Versioned Snapshot System,
                and Automatic System Recovery in one lightweight local defense stack. Threshold-based
                early warning using behavioral anomalies such as CPU spikes and high file access rate.
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

              <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
                <StatusCard
                  title="File Rate"
                  value={`${snapshot.metrics.files_per_second.toFixed(1)} /s`}
                  caption="Rolling files per second"
                  accent="blue"
                />
                <StatusCard
                  title="CPU"
                  value={`${cpuDisplayValue.toFixed(1)}%`}
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
                  title="Threat Confidence"
                  value={`${Math.round(threatConfidence)}%`}
                  caption="Behavioral certainty score"
                  accent={isUnderAttack ? 'rose' : 'amber'}
                />
                <StatusCard
                  title="Pipeline Level"
                  value={pipelineThreatLevel}
                  caption={`Score ${Math.round(pipelineThreatScore)}% • ${pipelineMode}`}
                  accent={pipelineAccent}
                />
              </div>
            </div>

            <div className="rounded-[1.75rem] border border-slate-800 bg-slate-900/70 p-5">
              <div className="text-sm uppercase tracking-[0.26em] text-slate-400">Protection Controls</div>
              <div className="mt-3 text-2xl font-semibold text-white">Auto protection loop</div>
              <p className="mt-2 text-sm leading-6 text-slate-300">
                The engine automatically protects configured system directories. Launch a
                simulation to observe Early Threat Detection, Active Threat Neutralization,
                and Automatic System Recovery.
              </p>
              <div className="mt-5 rounded-2xl border border-slate-700 bg-slate-950/70 px-4 py-3 text-sm text-slate-300">
                {snapshot.monitoring_message}
              </div>
              <div className="mt-4 grid grid-cols-2 gap-3">
                <button
                  type="button"
                  disabled={busy || isSimulating}
                  onClick={handleStart}
                  className="rounded-2xl bg-sky-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  Start Monitoring
                </button>
                <button
                  type="button"
                  disabled={busy || isSimulating}
                  onClick={handleStop}
                  className="rounded-2xl border border-slate-700 bg-slate-950/70 px-4 py-3 text-sm font-semibold text-white transition hover:border-slate-500 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  Stop Monitoring
                </button>
              </div>
              <button
                type="button"
                disabled={busy || isSimulating}
                onClick={handleRunAttackSimulation}
                className="mt-3 w-full rounded-2xl border border-amber-400/40 bg-amber-500/10 px-4 py-3 text-sm font-semibold text-amber-200 transition hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:border-slate-700 disabled:bg-slate-900/70 disabled:text-slate-500"
              >
                {isSimulating ? 'Running Simulation...' : 'Run Attack Simulation'}
              </button>
              <button
                type="button"
                disabled={busy || isSimulating || isRunningIntervention}
                onClick={handleSafeIntervention}
                className="mt-3 w-full rounded-2xl border border-sky-400/40 bg-sky-500/10 px-4 py-3 text-sm font-semibold text-sky-200 transition hover:bg-sky-500/20 disabled:cursor-not-allowed disabled:border-slate-700 disabled:bg-slate-900/70 disabled:text-slate-500"
              >
                {isRunningIntervention ? 'Running Safe Intervention...' : 'Run Safe Intervention'}
              </button>
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
                <div className="mt-2 flex items-center justify-between gap-3">
                  <span>Tracked Files</span>
                  <span className="text-slate-300">{trackedFiles}</span>
                </div>
                <div className="mt-2 flex items-center justify-between gap-3">
                  <span>DNA Mismatch Count</span>
                  <span className={dnaMismatchCount > 0 ? 'text-amber-300' : 'text-slate-400'}>
                    {dnaMismatchCount}
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
              {interventionMessage ? (
                <div className="mt-4 rounded-2xl border border-sky-400/30 bg-sky-500/10 p-4 text-sm text-sky-100">
                  {interventionMessage}
                </div>
              ) : null}
            </div>
          </div>
        </section>

        <section className="grid gap-6 xl:grid-cols-[1.4fr_0.9fr]">
          <ActivityChart data={chartData} />
          <AlertsPanel alerts={snapshot.alerts} />
        </section>

        <section className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
          <AttackInsightsPanel
            confidence={threatConfidence}
            attackSummary={attackSummary}
            fileStats={fileStats}
          />
          <SystemTimelinePanel
            timeline={timeline}
            onClearTimeline={handleClearLogs}
            isClearingTimeline={clearingLogs}
          />
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

        <InterventionPanel
          result={interventionResult}
          onRunIntervention={handleSafeIntervention}
          isRunningIntervention={isRunningIntervention}
          message={interventionMessage}
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
