import { useEffect, useMemo, useState } from 'react';

function severityClass(severity) {
  switch (severity) {
    case 'critical':
      return 'border-rose-400/30 bg-rose-500/10 text-rose-100';
    case 'high':
      return 'border-orange-400/30 bg-orange-500/10 text-orange-100';
    case 'medium':
      return 'border-amber-400/30 bg-amber-500/10 text-amber-100';
    default:
      return 'border-slate-700 bg-slate-900/70 text-slate-200';
  }
}

const ALERT_TTL_MS = 15 * 60 * 1000;

function alertKey(alert) {
  return [
    alert?.timestamp ?? '',
    alert?.title ?? '',
    alert?.details ?? '',
    alert?.status ?? '',
    alert?.severity ?? '',
  ].join('|');
}

function parseAlertTimestamp(timestamp) {
  if (typeof timestamp !== 'string' || !timestamp.trim()) {
    return Number.NaN;
  }

  const parsed = Date.parse(timestamp);
  if (Number.isFinite(parsed)) {
    return parsed;
  }

  // Normalize microseconds (Python ISO strings) so browser Date parsing remains reliable.
  const normalizedTimestamp = timestamp.replace(/(\.\d{3})\d+/, '$1');
  const normalized = Date.parse(normalizedTimestamp);
  return Number.isFinite(normalized) ? normalized : Number.NaN;
}

function isAlertWithinTtl(alert, nowMs) {
  const alertMs = parseAlertTimestamp(alert?.timestamp);
  if (!Number.isFinite(alertMs)) {
    return true;
  }
  return nowMs - alertMs <= ALERT_TTL_MS;
}

export default function AlertsPanel({ alerts }) {
  const [dismissedAlertKeys, setDismissedAlertKeys] = useState(() => new Set());

  const activeAlerts = useMemo(() => {
    const nowMs = Date.now();
    return alerts.filter((alert) => isAlertWithinTtl(alert, nowMs));
  }, [alerts]);

  const visibleAlerts = useMemo(
    () => activeAlerts.filter((alert) => !dismissedAlertKeys.has(alertKey(alert))),
    [activeAlerts, dismissedAlertKeys],
  );

  useEffect(() => {
    const activeKeys = new Set(activeAlerts.map((alert) => alertKey(alert)));

    setDismissedAlertKeys((current) => {
      let changed = false;
      const next = new Set();

      current.forEach((key) => {
        if (activeKeys.has(key)) {
          next.add(key);
          return;
        }
        changed = true;
      });

      return changed ? next : current;
    });
  }, [activeAlerts]);

  const dismissAlert = (alert) => {
    const key = alertKey(alert);
    setDismissedAlertKeys((current) => {
      if (current.has(key)) {
        return current;
      }
      const next = new Set(current);
      next.add(key);
      return next;
    });
  };

  return (
    <div className="rounded-3xl border border-slate-700/70 bg-slate-950/70 p-5 shadow-glow">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-sm uppercase tracking-[0.26em] text-rose-300/80">Alerts</div>
          <h2 className="mt-2 text-xl font-semibold text-white">Detection timeline</h2>
        </div>
        <div className="text-sm text-slate-400">{visibleAlerts.length} active entries</div>
      </div>
      <div className="mt-5 max-h-[34rem] space-y-3 overflow-y-auto pr-1">
        {visibleAlerts.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-700 bg-slate-900/50 p-5 text-sm text-slate-400">
            No alerts yet. The system is in SAFE mode.
          </div>
        ) : (
          visibleAlerts.map((alert, index) => {
            const rowKey = `${alertKey(alert)}-${index}`;

            return (
              <div key={rowKey} className={`rounded-2xl border p-4 ${severityClass(alert.severity)}`}>
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="font-semibold">{alert.title}</div>
                  <div className="flex items-center gap-2">
                    <div className="text-xs uppercase tracking-[0.22em] opacity-80">{alert.status}</div>
                    <button
                      type="button"
                      onClick={() => dismissAlert(alert)}
                      className="rounded-full border border-current/35 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.14em] opacity-80 transition hover:opacity-100"
                      aria-label={`Remove alert ${alert.title ?? ''}`}
                    >
                      X
                    </button>
                  </div>
                </div>
                <p className="mt-2 text-sm leading-6 opacity-90">{alert.details}</p>
                <div className="mt-3 text-xs text-slate-400">{alert.timestamp}</div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
