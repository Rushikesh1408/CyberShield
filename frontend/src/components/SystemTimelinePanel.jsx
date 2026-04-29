function formatTimestamp(timestamp) {
  if (!timestamp) {
    return 'Live';
  }

  const value = new Date(timestamp);
  if (Number.isNaN(value.getTime())) {
    return timestamp;
  }

  return value.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function toneForSeverity(severity) {
  switch (severity) {
    case 'critical':
      return {
        dot: 'bg-rose-400',
        border: 'border-rose-400/30',
        background: 'bg-rose-500/10',
      };
    case 'warning':
      return {
        dot: 'bg-orange-400',
        border: 'border-orange-400/30',
        background: 'bg-orange-500/10',
      };
    case 'info':
      return {
        dot: 'bg-sky-400',
        border: 'border-sky-400/30',
        background: 'bg-sky-500/10',
      };
    default:
      return {
        dot: 'bg-emerald-400',
        border: 'border-emerald-400/30',
        background: 'bg-emerald-500/10',
      };
  }
}

export default function SystemTimelinePanel({
  timeline,
  onClearTimeline,
  isClearingTimeline = false,
}) {
  const entries = Array.isArray(timeline) ? timeline : [];
  const canClear = typeof onClearTimeline === 'function' && entries.length > 1;

  return (
    <section className="rounded-3xl border border-slate-700/70 bg-slate-950/70 p-5 shadow-glow">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm uppercase tracking-[0.26em] text-sky-300/80">System Lifecycle</div>
          <h2 className="mt-2 text-xl font-semibold text-white">SAFE to SYSTEM_SAFE timeline</h2>
        </div>
        <button
          type="button"
          onClick={onClearTimeline}
          disabled={!canClear || isClearingTimeline}
          className="rounded-xl border border-slate-700 bg-slate-900/70 px-3 py-2 text-xs font-semibold text-slate-200 transition hover:border-slate-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {isClearingTimeline ? 'Clearing...' : 'Clear Timeline'}
        </button>
      </div>

      <div className="relative mt-5 max-h-[34rem] space-y-3 overflow-y-auto pl-5 pr-1">
        <div className="pointer-events-none absolute bottom-2 left-[9px] top-2 w-px bg-slate-700" />
        {entries.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-700 bg-slate-900/50 p-5 text-sm text-slate-400">
            No state transitions captured yet.
          </div>
        ) : (
          entries.map((item, index) => {
            const tone = toneForSeverity(String(item.severity || 'safe'));
            return (
              <div
                key={`${item.state}-${item.timestamp || index}`}
                className={`relative rounded-2xl border p-4 transition-all duration-500 ${tone.border} ${tone.background}`}
              >
                <div className={`absolute -left-[20px] top-5 h-3 w-3 rounded-full ${tone.dot}`} />
                <div className="flex items-center justify-between gap-3">
                  <div className="text-sm font-semibold text-white">{item.state}</div>
                  <div className="text-xs text-slate-300">{formatTimestamp(item.timestamp)}</div>
                </div>
                <div className="mt-1 text-sm text-slate-200">{item.description}</div>
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}
