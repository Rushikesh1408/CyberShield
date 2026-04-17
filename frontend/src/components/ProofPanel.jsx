import { useEffect, useMemo, useRef, useState } from 'react';

function ShieldIcon({ className = '' }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <path d="M12 3 4 7v6c0 5 3.4 8.4 8 9 4.6-.6 8-4 8-9V7l-8-4Z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

function LockIcon({ className = '' }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <rect x="4" y="10" width="16" height="11" rx="2" />
      <path d="M8 10V7a4 4 0 1 1 8 0v3" />
    </svg>
  );
}

function RestoreIcon({ className = '' }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <path d="M3 12a9 9 0 1 0 2.6-6.4" />
      <path d="M3 4v5h5" />
      <path d="M12 8v4l2.6 2.6" />
    </svg>
  );
}

function TrendIcon({ className = '' }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <path d="M3 17 9 11l4 4 8-8" />
      <path d="M16 7h5v5" />
    </svg>
  );
}

function useAnimatedNumber(targetValue, durationMs = 480) {
  const [animatedValue, setAnimatedValue] = useState(Number(targetValue) || 0);
  const previousValueRef = useRef(Number(targetValue) || 0);

  useEffect(() => {
    const start = previousValueRef.current;
    const end = Number(targetValue) || 0;
    if (start === end) {
      setAnimatedValue(end);
      return;
    }

    let rafId = 0;
    const startedAt = performance.now();
    const tick = (now) => {
      const progress = Math.min((now - startedAt) / durationMs, 1);
      const eased = 1 - (1 - progress) * (1 - progress);
      setAnimatedValue(start + (end - start) * eased);
      if (progress < 1) {
        rafId = requestAnimationFrame(tick);
      } else {
        previousValueRef.current = end;
      }
    };

    rafId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafId);
  }, [targetValue, durationMs]);

  return animatedValue;
}

function MetricCard({ title, value, icon: Icon, iconTone, valueTone, suffix = '', subtitle }) {
  const animatedValue = useAnimatedNumber(value);
  const formatted = useMemo(() => Math.round(animatedValue).toLocaleString(), [animatedValue]);
  const metricKey = title.toUpperCase().replace(/\s+/g, '_');

  return (
    <article className="rounded-2xl border border-slate-700/70 bg-slate-900/60 p-4 transition duration-200 hover:-translate-y-0.5 hover:border-slate-600">
      <div className="flex items-center justify-between gap-3 border-b border-slate-800/80 pb-2.5">
        <h3 className="text-[11px] uppercase tracking-[0.2em] text-slate-500">{title}</h3>
        <Icon className={`h-5 w-5 ${iconTone}`} />
      </div>

      <div className="mt-3 flex items-end justify-between gap-4">
        <div className={`text-3xl font-semibold tracking-tight ${valueTone}`}>
          {formatted}
          {suffix}
        </div>
        <span className="rounded-md border border-slate-800 bg-slate-950/70 px-2 py-1 text-[10px] uppercase tracking-[0.16em] text-slate-500">
          {metricKey}
        </span>
      </div>

      <p className="mt-2 text-xs text-slate-500">{subtitle}</p>
    </article>
  );
}

function ConfidenceBadge({ confidence }) {
  const tone = confidence >= 70
    ? 'border-rose-500/40 bg-rose-500/10 text-rose-200'
    : confidence >= 40
      ? 'border-amber-500/40 bg-amber-500/10 text-amber-200'
      : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200';

  const label = confidence >= 70 ? 'HIGH' : confidence >= 40 ? 'MEDIUM' : 'LOW';

  return (
    <span className={`rounded-full border px-2.5 py-1 text-[11px] uppercase tracking-[0.18em] ${tone}`}>
      Confidence {label}
    </span>
  );
}

export default function ProofPanel({ filesProtected, filesEncrypted, filesRecovered, threatConfidence }) {
  const confidence = Number(threatConfidence) || 0;
  const confidenceTone = confidence >= 70 ? 'text-rose-300' : confidence >= 40 ? 'text-amber-300' : 'text-emerald-300';
  const confidenceIconTone = confidence >= 70 ? 'text-rose-400' : confidence >= 40 ? 'text-amber-400' : 'text-emerald-400';

  return (
    <section className="rounded-3xl border border-slate-800/80 bg-slate-900/35 p-5 lg:p-6">
      <div className="mb-5 flex items-center justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Proof Panel</p>
          <h2 className="mt-1 text-xl font-semibold text-white">Live Defense Proof</h2>
        </div>
        <ConfidenceBadge confidence={confidence} />
      </div>

      <div className="mb-4 rounded-2xl border border-slate-800 bg-slate-950/65 px-4 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-slate-500">
        VERIFIED TELEMETRY • REAL-TIME COUNTERS
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <MetricCard
          title="Files Protected"
          value={filesProtected}
          icon={ShieldIcon}
          iconTone="text-emerald-400"
          valueTone="text-emerald-200"
          subtitle="Versioned snapshots secured"
        />
        <MetricCard
          title="Files Encrypted"
          value={filesEncrypted}
          icon={LockIcon}
          iconTone="text-rose-400"
          valueTone="text-rose-200"
          subtitle="Observed during attack events"
        />
        <MetricCard
          title="Files Recovered"
          value={filesRecovered}
          icon={RestoreIcon}
          iconTone="text-emerald-400"
          valueTone="text-emerald-200"
          subtitle="Restored by automated recovery"
        />
        <MetricCard
          title="Threat Confidence"
          value={confidence}
          icon={TrendIcon}
          iconTone={confidenceIconTone}
          valueTone={confidenceTone}
          suffix="%"
          subtitle="Behavioral confidence score"
        />
      </div>
    </section>
  );
}
