import { useState } from 'react';

function nameFromPath(pathValue) {
  if (!pathValue || typeof pathValue !== 'string') {
    return '';
  }
  const normalized = pathValue.replace(/\\/g, '/').split('/').filter(Boolean);
  return normalized.at(-1) || pathValue;
}

function humanizeEvent(value) {
  if (!value || typeof value !== 'string') {
    return 'Unknown event';
  }
  return value
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function monitoredTargetLabel(log) {
  if (log.file_name) {
    return log.file_name;
  }

  if (log.file_path) {
    return nameFromPath(log.file_path);
  }

  const metadataPaths = Array.isArray(log.metadata?.paths) ? log.metadata.paths : [];
  if (metadataPaths.length > 0) {
    return nameFromPath(metadataPaths[0]);
  }

  const restoredPaths = Array.isArray(log.metadata?.restored) ? log.metadata.restored : [];
  if (restoredPaths.length > 0) {
    return nameFromPath(restoredPaths[0]);
  }

  return 'Protected directory';
}

function detailLines(log) {
  const lines = [];
  lines.push(`Event: ${log.event ?? log.message ?? 'unknown_event'}`);
  lines.push(`Type: ${String(log.event_type ?? log.level ?? 'info').toLowerCase()}`);
  lines.push(`Action: ${log.action ?? 'none'}`);
  lines.push(`CPU usage: ${Number(log.cpu_usage ?? 0).toFixed(2)}%`);
  lines.push(`File rate: ${Number(log.file_rate ?? 0).toFixed(2)} events/s`);
  lines.push(`Timestamp: ${log.timestamp ?? 'N/A'}`);

  if (log.process_name) {
    lines.push(`Process: ${log.process_name}`);
  }
  if (log.file_path) {
    lines.push(`Path: ${log.file_path}`);
  }

  const metadataPaths = Array.isArray(log.metadata?.paths) ? log.metadata.paths : [];
  if (metadataPaths.length > 0) {
    lines.push(`Monitored paths: ${metadataPaths.join(' | ')}`);
  }

  const restoredCount = log.metadata?.restored_count;
  if (typeof restoredCount === 'number') {
    lines.push(`Restored files: ${restoredCount}`);
  }

  const destinationPath = log.metadata?.destination_path;
  if (typeof destinationPath === 'string' && destinationPath) {
    lines.push(`Renamed to: ${destinationPath}`);
  }

  const restoredPaths = Array.isArray(log.metadata?.restored) ? log.metadata.restored : [];
  if (restoredPaths.length > 0) {
    lines.push(`Restored paths: ${restoredPaths.join(' | ')}`);
  }

  return lines;
}

export default function LogsTimeline({ logs, onClearLogs, isClearingLogs = false }) {
  const [expandedRows, setExpandedRows] = useState({});

  const toggleRow = (rowKey) => {
    setExpandedRows((current) => ({
      ...current,
      [rowKey]: !current[rowKey],
    }));
  };

  return (
    <div className="rounded-3xl border border-slate-700/70 bg-slate-950/70 p-5 shadow-glow">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-sm uppercase tracking-[0.26em] text-cyan-300/80">Logs</div>
          <h2 className="mt-2 text-xl font-semibold text-white">Live system timeline</h2>
        </div>
        <button
          type="button"
          onClick={onClearLogs}
          disabled={isClearingLogs || logs.length === 0}
          className="rounded-xl border border-rose-400/40 bg-rose-500/10 px-3 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-rose-200 transition hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:border-slate-700 disabled:bg-slate-900/70 disabled:text-slate-500"
        >
          {isClearingLogs ? 'Clearing...' : 'Clear Logs'}
        </button>
      </div>
      <div className="mt-5 max-h-[34rem] space-y-3 overflow-y-auto pr-1">
        {logs.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-700 bg-slate-900/50 p-5 text-sm text-slate-400">
            No log entries available yet.
          </div>
        ) : (
          logs.map((log, index) => {
            const rowKey = `${log.timestamp}-${index}`;
            const expanded = Boolean(expandedRows[rowKey]);
            const levelLabel = String(log.event_type ?? log.level ?? 'info').toUpperCase();
            const title = humanizeEvent(log.event ?? log.message);

            return (
              <div key={rowKey} className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="text-sm font-medium text-white">{title}</div>
                  <button
                    type="button"
                    onClick={() => toggleRow(rowKey)}
                    className="rounded-full border border-slate-700 px-2 py-1 text-[11px] uppercase tracking-[0.2em] text-slate-400 transition hover:border-sky-400 hover:text-sky-300"
                    aria-expanded={expanded}
                  >
                    {levelLabel}
                  </button>
                </div>

                <div className="mt-2 text-xs leading-5 text-slate-400">
                  Monitored target: <span className="text-slate-200">{monitoredTargetLabel(log)}</span>
                </div>

                {expanded ? (
                  <div className="mt-3 rounded-xl border border-slate-800 bg-slate-950/70 p-3 text-xs leading-5 text-slate-300">
                    {detailLines(log).map((line) => (
                      <div key={`${rowKey}-${line}`}>{line}</div>
                    ))}
                  </div>
                ) : null}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
