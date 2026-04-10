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

export default function AlertsPanel({ alerts }) {
  return (
    <div className="rounded-3xl border border-slate-700/70 bg-slate-950/70 p-5 shadow-glow">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-sm uppercase tracking-[0.26em] text-rose-300/80">Alerts</div>
          <h2 className="mt-2 text-xl font-semibold text-white">Detection timeline</h2>
        </div>
        <div className="text-sm text-slate-400">{alerts.length} active entries</div>
      </div>
      <div className="mt-5 space-y-3">
        {alerts.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-700 bg-slate-900/50 p-5 text-sm text-slate-400">
            No alerts yet. The system is in SAFE mode.
          </div>
        ) : (
          alerts.map((alert, index) => (
            <div
              key={`${alert.timestamp}-${index}`}
              className={`rounded-2xl border p-4 ${severityClass(alert.severity)}`}
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="font-semibold">{alert.title}</div>
                <div className="text-xs uppercase tracking-[0.22em] opacity-80">
                  {alert.status}
                </div>
              </div>
              <p className="mt-2 text-sm leading-6 opacity-90">{alert.details}</p>
              <div className="mt-3 text-xs text-slate-400">{alert.timestamp}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
