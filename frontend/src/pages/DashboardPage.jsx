import { useEffect, useMemo, useState } from 'react';

import ActivityChart from '../components/ActivityChart';
import AttackStoryPanel from '../components/AttackStoryPanel';
import AttackInsightsPanel from '../components/AttackInsightsPanel';
import AlertsPanel from '../components/AlertsPanel';
import BackupRecoveryPanel from '../components/BackupRecoveryPanel';
import EmergencyPanel from '../components/EmergencyPanel';
import FingerprintPanel from '../components/FingerprintPanel';
import LogsTimeline from '../components/LogsTimeline';
import ProofPanel from '../components/ProofPanel';
import StatusCard from '../components/StatusCard';
import SystemTimelinePanel from '../components/SystemTimelinePanel';
import InterventionPanel from '../components/InterventionPanel';

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';
// API key is required — never falls back to a hardcoded value in production
const API_KEY = import.meta.env.VITE_API_KEY ?? '';

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

const initialAttackStory = {
  attackSourcePath: '',
  processDisplay: '',
  filesAffected: 0,
  actionTaken: '',
  finalStatus: 'SAFE',
  timeline: {
    detected: false,
    terminated: false,
    restored: false,
  },
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

/**
 * Fetch JSON from the API.
 * Automatically attaches x-api-key header on every request.
 * The backend returns {status, data, error} — this helper unwraps `data`.
 */
function buildActivitySample(metrics, {
  snapshot,
  attackSummary,
  recentLogs,
  timeline,
  isSimulating = false,
} = {}) {
  const filesPerSecond = Number(metrics?.files_per_second ?? 0);
  const modifications = Number(metrics?.modifications ?? 0);
  const metricSignal = Math.max(filesPerSecond, modifications);
  const isUnderAttack = String(snapshot?.status ?? '').toUpperCase() === 'UNDER_ATTACK' || Boolean(isSimulating);

  // When system is safe and no simulation is running, graph must reflect only real metrics.
  if (!isUnderAttack) {
    return {
      label: timeLabel(new Date().toISOString()),
      activity_signal: metricSignal,
      files_per_second: filesPerSecond,
    };
  }

  const pipelineMetrics = snapshot?.core_pipeline?.last_assessment?.metrics ?? snapshot?.core_pipeline?.threat?.metrics ?? {};
  const pipelineFileRate = Number(pipelineMetrics?.file_activity_rate ?? 0);
  const pipelineFileCount = Number(pipelineMetrics?.file_activity_count ?? 0);
  const encryptedCount = Number(attackSummary?.files_encrypted ?? 0);
  const recoveredCount = Number(attackSummary?.files_recovered ?? 0);
  const attackBoost = snapshot?.status === 'UNDER_ATTACK' ? 25 : 0;
  const nowMs = Date.now();
  const recentEventBurst = Array.isArray(recentLogs)
    ? recentLogs.filter((entry) => {
      const ts = Date.parse(String(entry?.timestamp ?? ''));
      return Number.isFinite(ts) && nowMs - ts <= 6000;
    }).length
    : 0;
  const timelinePulse = Array.isArray(timeline) && timeline.length > 0 ? 5 : 0;

  return {
    label: timeLabel(new Date().toISOString()),
    activity_signal: Math.max(
      metricSignal,
      pipelineFileRate,
      pipelineFileCount,
      encryptedCount,
      recoveredCount,
      attackBoost,
      recentEventBurst * 20,
      timelinePulse,
    ),
    files_per_second: Math.max(filesPerSecond, pipelineFileRate, attackBoost, recentEventBurst),
  };
}


async function fetchJson(path, options = {}, timeoutMs = 8000) {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);

  const method = (options.method ?? 'GET').toUpperCase();
  const headers = { ...(options.headers ?? {}) };

  // Always include API key
  headers['x-api-key'] = API_KEY;

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
    let errorMsg = `Request failed: ${response.status}`;
    try {
      const payload = await response.json();
      errorMsg = payload.detail ?? payload.message ?? errorMsg;
    } catch {
      // ignore JSON parse failure
    }
    throw new Error(String(errorMsg));
  }

  const json = await response.json();
  // Unwrap standardised envelope {status, data, error}
  if (json && typeof json === 'object' && 'data' in json && json.status === 'success') {
    return json.data;
  }
  // Legacy / non-standard response — return as-is
  return json;
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
  const [attackStory, setAttackStory] = useState(initialAttackStory);
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
    const [statusResult, logsResult, fingerprintsResult] =
      await Promise.allSettled([
        fetchJson('/api/status'),
        fetchJson('/api/logs'),
        fetchJson('/api/fingerprints'),
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

      if (logsResult.status === 'fulfilled') {
        nextSnapshot.logs = logsResult.value.logs ?? [];
      }

      if (fingerprintsResult.status === 'fulfilled') {
        nextSnapshot.fingerprints = fingerprintsResult.value.fingerprints ?? [];
      }

      return nextSnapshot;
    });

    const requestErrors = [statusResult, logsResult, fingerprintsResult].filter(
      (result) => result.status === 'rejected',
    );

    if (requestErrors.length === 3) {
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

  const loadAlertsLayer = async () => {
    try {
      const alertsData = await fetchJson('/api/alerts', {}, 6000);
      setSnapshot((current) => ({
        ...current,
        alerts: Array.isArray(alertsData.alerts) ? alertsData.alerts : [],
      }));
    } catch {
      // Keep last alerts if this layer fails temporarily.
    }
  };

  const loadMetricsLayer = async () => {
    try {
      const metricsData = await fetchJson('/api/metrics', {}, 6000);
      setSnapshot((current) => {
        const nextSnapshot = {
          ...current,
          metrics: metricsData.metrics ?? initialSnapshot.metrics,
        };
        const graphHistory = (metricsData.history ?? []).map((entry) => ({
          activity_signal: Math.max(
            Number(entry.files_per_second ?? 0),
            Number(entry.modifications ?? 0),
          ),
          label: timeLabel(entry.timestamp),
          files_per_second: Number(entry.files_per_second ?? 0),
        }));
        const latestHistoryPoint = graphHistory.length > 0 ? graphHistory[graphHistory.length - 1] : null;
        const liveSample = buildActivitySample(nextSnapshot.metrics, {
          snapshot: nextSnapshot,
          attackSummary,
          recentLogs: nextSnapshot.logs,
          timeline,
          isSimulating,
        });
        setHistory((currentHistory) => {
          if (currentHistory.length === 0 && graphHistory.length > 0) {
            // Seed chart from backend history once, then rely on live polling samples.
            return [...graphHistory.slice(-119), liveSample];
          }

          return [...currentHistory.slice(-119), liveSample];
        });
        return nextSnapshot;
      });
    } catch {
      setHistory((currentHistory) => {
        const liveSample = buildActivitySample(snapshot.metrics, {
          snapshot,
          attackSummary,
          recentLogs: snapshot.logs,
          timeline,
          isSimulating,
        });
        return [...currentHistory.slice(-119), liveSample];
      });
    }
  };

  const loadSimulationLayer = async () => {
    try {
      const simulationStatus = await fetchJson('/api/simulate/status', {}, 6000);
      const state = String(simulationStatus.state ?? '').toLowerCase();

      if (state === 'running') {
        setIsSimulating(true);
        return;
      }

      if (state === 'failed') {
        setIsSimulating(false);
        setError(String(simulationStatus.error || 'simulation_failed'));
        return;
      }

      if (state === 'completed' && isSimulating) {
        const result = simulationStatus.result ?? {};
        const summary = result.attack_summary ?? {};
        const encrypted = Number(summary.files_encrypted ?? 0);
        const recovered = Number(summary.files_recovered ?? 0);
        const reportReady = Boolean(result.report_ready);

        setEmergencyMessage(
          reportReady
            ? `Simulation completed. Encrypted: ${encrypted}, Recovered: ${recovered}. Report generated.`
            : `Simulation completed. Encrypted: ${encrypted}, Recovered: ${recovered}. Report still pending.`,
        );
        setIsSimulating(false);
        setError('');
        await loadSnapshot();
        await loadAlertsLayer();
        await loadMetricsLayer();
        await loadSystemIntelligence();
        await loadBackupStatus();
        return;
      }

      if (state === 'idle' && isSimulating) {
        setIsSimulating(false);
      }
    } catch {
      // Keep current simulation state if polling fails once.
    }
  };

  useEffect(() => {
    loadSnapshot();
    loadAlertsLayer();
    loadMetricsLayer();
    loadSimulationLayer();
    loadBackupStatus();
    loadEmergencyContact();
    loadSystemIntelligence();

    const snapshotInterval = window.setInterval(loadSnapshot, 2000);
    const alertsInterval = window.setInterval(loadAlertsLayer, 2000);
    const metricsInterval = window.setInterval(loadMetricsLayer, 1500);
    const simulationInterval = window.setInterval(loadSimulationLayer, 1500);
    const backupInterval = window.setInterval(loadBackupStatus, 10000);
    const intelligenceInterval = window.setInterval(loadSystemIntelligence, 4000);

    return () => {
      window.clearInterval(snapshotInterval);
      window.clearInterval(alertsInterval);
      window.clearInterval(metricsInterval);
      window.clearInterval(simulationInterval);
      window.clearInterval(backupInterval);
      window.clearInterval(intelligenceInterval);
    };
  }, []);

  const isUnderAttack = snapshot.status === 'THREAT' || snapshot.status === 'UNDER_ATTACK';
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

  useEffect(() => {
    const logs = Array.isArray(snapshot.logs) ? snapshot.logs : [];
    const attackEvents = new Set([
      'attack_detected',
      'process_killed',
      'process_suspended',
      'active_threat_neutralization',
      'automatic_system_recovery',
      'files_restored',
      'file_restored',
      'attack_report_generated',
    ]);

    const latestAttackLog = logs.find((item) => {
      const event = String(item?.event || '').toLowerCase();
      const eventType = String(item?.event_type || item?.level || '').toLowerCase();
      return attackEvents.has(event) || eventType === 'critical';
    });

    const metadata = latestAttackLog?.metadata && typeof latestAttackLog.metadata === 'object'
      ? latestAttackLog.metadata
      : {};

    const monitoredPaths = Array.isArray(metadata.paths) ? metadata.paths : [];
    const sourcePath = String(
      latestAttackLog?.file_path || metadata.file_path || monitoredPaths[0] || metadata.destination_path || '',
    );

    const processName = String(
      latestAttackLog?.process_name || metadata.process_name || metadata.top_process || '',
    ).trim();
    const processPid = Number(metadata.pid ?? metadata.process_pid ?? 0);
    const processDisplay = processName
      ? processPid > 0
        ? `${processName} (PID ${processPid})`
        : processName
      : processPid > 0
        ? `PID ${processPid}`
        : '';

    const affectedFromLogs = Number(
      metadata.files_affected ?? metadata.modifications ?? metadata.file_activity_count ?? 0,
    );
    const filesAffected = Math.max(
      Number(attackSummary.files_encrypted ?? 0),
      affectedFromLogs,
    );

    const timelineStates = new Set(
      (Array.isArray(timeline) ? timeline : []).map((item) => String(item?.state || '').toUpperCase()),
    );
    const detected = timelineStates.has('ATTACK_DETECTED') || Boolean(latestAttackLog);
    const terminated =
      timelineStates.has('PROCESS_TERMINATED') ||
      timelineStates.has('PROCESS_SUSPENDED') ||
      ['process_killed', 'process_suspended', 'active_threat_neutralization'].includes(
        String(latestAttackLog?.event || '').toLowerCase(),
      );
    const restored =
      timelineStates.has('FILES_RESTORED') ||
      ['automatic_system_recovery', 'files_restored', 'file_restored'].includes(
        String(latestAttackLog?.event || '').toLowerCase(),
      ) ||
      Number(attackSummary.files_recovered || 0) > 0;

    const actionParts = [];
    if (terminated) {
      actionParts.push('Process terminated');
    }
    if (restored) {
      actionParts.push('files restored');
    }
    if (!terminated && !restored && detected) {
      actionParts.push('Threat detected and queued');
    }

    const nextStory = {
      attackSourcePath: sourcePath,
      processDisplay,
      filesAffected,
      actionTaken: actionParts.join(' + '),
      finalStatus: String(snapshot.status || 'SAFE').toUpperCase(),
      timeline: {
        detected,
        terminated,
        restored,
      },
    };

    const hasSignal = Boolean(sourcePath || processDisplay || filesAffected > 0 || detected);

    setAttackStory((current) => {
      if (hasSignal) {
        return nextStory;
      }
      if (current.attackSourcePath || current.processDisplay || current.filesAffected > 0) {
        return {
          ...current,
          finalStatus: nextStory.finalStatus,
          timeline: nextStory.timeline.detected || nextStory.timeline.terminated || nextStory.timeline.restored
            ? nextStory.timeline
            : current.timeline,
        };
      }
      return {
        ...current,
        finalStatus: nextStory.finalStatus,
      };
    });
  }, [attackSummary.files_encrypted, attackSummary.files_recovered, snapshot.logs, snapshot.status, timeline]);

  const handleStart = async () => {
    setBusy(true);
    try {
      await fetchJson('/api/start', { method: 'POST' }, 20000);
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
      await fetchJson(
        '/api/simulate/attack',
        {
          method: 'POST',
          body: JSON.stringify({ level: 'high', wait_timeout: 30 }),
        },
        12000,
      );
      setEmergencyMessage('Simulation started. Monitoring progress...');
      await loadSimulationLayer();
      setError('');
    } catch (requestError) {
      setError(requestError.message);
      setIsSimulating(false);
    } finally {
      // Keep isSimulating controlled by simulation status polling layer.
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
      setBackupMessage(`Backup completed. Created: ${response.created ?? 0} snapshot(s).`);
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
      await fetchJson('/api/recover', {
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
        headers: { 'x-api-key': API_KEY },
      });
      window.clearTimeout(timeoutId);

      if (!response.ok) {
        let message = `Request failed: ${response.status}`;
        try {
          const payload = await response.json();
          message = payload.detail ?? payload.message ?? message;
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
                Real-Time Ransomware Defense System
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
                  value={`${(snapshot.metrics.files_per_second ?? 0).toFixed(1)} /s`}
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
                  value={snapshot.metrics.modifications ?? 0}
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
                  id="btn-start-monitoring"
                  disabled={busy || isSimulating}
                  onClick={handleStart}
                  className="rounded-2xl bg-sky-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  Start Monitoring
                </button>
                <button
                  type="button"
                  id="btn-stop-monitoring"
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

        <ProofPanel
          filesProtected={Math.max(Number(fileStats.files_protected ?? 0), Number(attackSummary.files_protected ?? 0))}
          filesEncrypted={Number(attackSummary.files_encrypted ?? 0)}
          filesRecovered={Math.max(Number(fileStats.files_recovered ?? 0), Number(attackSummary.files_recovered ?? 0))}
          threatConfidence={threatConfidence}
        />

        <section className="grid gap-6 xl:grid-cols-[1.4fr_0.9fr]">
          <ActivityChart data={chartData} />
          <AlertsPanel alerts={snapshot.alerts} />
        </section>

        <AttackStoryPanel story={attackStory} />

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
