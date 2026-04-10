export default function LogsTimeline({ logs }) {
  return (
    <div className="rounded-3xl border border-slate-700/70 bg-slate-950/70 p-5 shadow-glow">
      <div>
        <div className="text-sm uppercase tracking-[0.26em] text-cyan-300/80">Logs</div>
        <h2 className="mt-2 text-xl font-semibold text-white">Live system timeline</h2>
      </div>
      <div className="mt-5 space-y-3">
        {logs.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-700 bg-slate-900/50 p-5 text-sm text-slate-400">
            No log entries available yet.
          </div>
        ) : (
          logs.map((log, index) => (
            <div key={`${log.timestamp}-${index}`} className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="text-sm font-medium text-white">{log.message}</div>
                <span className="rounded-full border border-slate-700 px-2 py-1 text-[11px] uppercase tracking-[0.2em] text-slate-400">
                  {log.level}
                </span>
              </div>
              <div className="mt-2 text-xs leading-5 text-slate-400">
                {log.timestamp}
                {log.process_name ? ` · ${log.process_name}` : ''}
                {log.file_path ? ` · ${log.file_path}` : ''}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
