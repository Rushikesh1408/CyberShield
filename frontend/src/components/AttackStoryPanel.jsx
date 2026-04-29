function Pill({ label, active, tone = 'slate' }) {
  const toneClass =
    tone === 'green'
      ? active
        ? 'border-emerald-500/50 bg-emerald-500/15 text-emerald-200'
        : 'border-emerald-500/20 bg-transparent text-slate-500'
      : tone === 'red'
        ? active
          ? 'border-rose-500/50 bg-rose-500/15 text-rose-200'
          : 'border-rose-500/20 bg-transparent text-slate-500'
        : active
          ? 'border-sky-500/50 bg-sky-500/15 text-sky-200'
          : 'border-slate-700 bg-transparent text-slate-500';

  return (
    <span className={`rounded-full border px-2.5 py-1 text-[11px] uppercase tracking-[0.18em] ${toneClass}`}>
      {label}
    </span>
  );
}

function valueOrFallback(value, fallback = 'n/a') {
  const normalized = String(value ?? '').trim();
  return normalized || fallback;
}

function StoryRow({ label, value, valueClassName = 'text-slate-200', wrap = false }) {
  return (
    <div className="grid grid-cols-[10rem_1fr] items-start gap-3 border-b border-slate-800/80 py-2.5 last:border-b-0">
      <span className="text-[11px] uppercase tracking-[0.2em] text-slate-500">{label}</span>
      <span className={`${wrap ? 'break-all' : 'truncate'} ${valueClassName}`}>{value}</span>
    </div>
  );
}

export default function AttackStoryPanel({ story }) {
  const isSafe = String(story.finalStatus || '').toUpperCase() === 'SAFE';
  const statusText = isSafe ? 'SYSTEM SAFE' : 'UNDER ATTACK';
  const statusTone = isSafe ? 'text-emerald-300' : 'text-rose-300';

  return (
    <section className="rounded-3xl border border-slate-800/80 bg-slate-950/70 p-5 lg:p-6">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Attack Story</p>
          <h2 className="mt-1 text-xl font-semibold text-white">Incident Intelligence</h2>
          <p className="mt-1 text-sm text-slate-400">Latest known attack context, preserved after recovery.</p>
        </div>
        <span
          className={`rounded-full border px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.14em] ${
            isSafe
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
              : 'border-rose-500/40 bg-rose-500/10 text-rose-200'
          }`}
        >
          {isSafe ? 'SYSTEM SAFE' : 'UNDER ATTACK'}
        </span>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-4 font-mono text-sm text-slate-200">
        <div className="mb-3 flex items-center justify-between border-b border-slate-800 pb-2">
          <span className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Incident Console</span>
          <span className={`text-xs uppercase tracking-[0.18em] ${statusTone}`}>{statusText}</span>
        </div>

        <div className="space-y-0">
          <StoryRow label="Attack Source" value={valueOrFallback(story.attackSourcePath)} wrap />
          <StoryRow label="Process" value={valueOrFallback(story.processDisplay)} />
          <StoryRow label="Files Affected" value={Number(story.filesAffected || 0).toLocaleString()} />
          <StoryRow label="Action Taken" value={valueOrFallback(story.actionTaken)} wrap />
          <StoryRow label="Final Status" value={statusText} valueClassName={statusTone} />
        </div>

        <div className="mt-4 border-t border-slate-800 pt-4">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Timeline</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Pill label="Detected" active={Boolean(story.timeline?.detected)} tone="red" />
            <span className="text-slate-600">→</span>
            <Pill label="Terminated" active={Boolean(story.timeline?.terminated)} tone="red" />
            <span className="text-slate-600">→</span>
            <Pill label="Restored" active={Boolean(story.timeline?.restored)} tone="green" />
          </div>
        </div>
      </div>
    </section>
  );
}
