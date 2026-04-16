function formatActionList(actions) {
  if (!Array.isArray(actions) || actions.length === 0) {
    return 'No intervention actions were needed.';
  }

  return actions.join(' • ');
}

function processCountLabel(items) {
  if (!Array.isArray(items)) {
    return 0;
  }

  return items.length;
}

export default function InterventionPanel({
  result,
  onRunIntervention,
  isRunningIntervention,
  message,
}) {
  const status = String(result?.status ?? 'SAFE').toUpperCase();
  const protectedFiles = Number(result?.files_protected ?? 0);
  const recoveredFiles = Number(result?.files_recovered ?? 0);
  const suspiciousCount = processCountLabel(result?.suspicious_processes);
  const confirmedCount = processCountLabel(result?.confirmed_processes);

  return (
    <section className="rounded-3xl border border-slate-700/70 bg-slate-950/70 p-5 shadow-glow">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="text-sm uppercase tracking-[0.26em] text-sky-300/80">Safe Intervention System</div>
          <h2 className="mt-2 text-xl font-semibold text-white">Detect, Suspend, Restore</h2>
        </div>
        <button
          type="button"
          onClick={onRunIntervention}
          disabled={isRunningIntervention}
          className="rounded-xl border border-sky-400/40 bg-sky-500/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-sky-200 transition hover:bg-sky-500/20 disabled:cursor-not-allowed disabled:border-slate-700 disabled:bg-slate-900/70 disabled:text-slate-500"
        >
          {isRunningIntervention ? 'Running...' : 'Trigger Safe Intervention'}
        </button>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Status</div>
          <div className="mt-2 text-lg font-semibold text-emerald-300">{status}</div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Files Protected</div>
          <div className="mt-2 text-lg font-semibold text-white">{protectedFiles}</div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Files Recovered</div>
          <div className="mt-2 text-lg font-semibold text-white">{recoveredFiles}</div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
          <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Suspicious Processes</div>
          <div className="mt-2 text-lg font-semibold text-white">{suspiciousCount}</div>
        </div>
      </div>

      <div className="mt-5 rounded-2xl border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-300">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <span className="text-xs uppercase tracking-[0.22em] text-slate-500">Action Summary</span>
          <span className="text-slate-200">Confirmed processes: {confirmedCount}</span>
        </div>
        <div className="mt-3 text-slate-200">{formatActionList(result?.action_taken)}</div>
      </div>

      {message ? (
        <div className="mt-5 rounded-xl border border-slate-700 bg-slate-950/80 p-3 text-sm text-slate-300">
          {message}
        </div>
      ) : null}
    </section>
  );
}