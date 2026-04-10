import { useEffect, useState } from 'react';

function useAnimatedNumber(targetValue, duration = 700) {
  const sanitizedTarget = Number.isFinite(Number(targetValue)) ? Number(targetValue) : 0;
  const [displayValue, setDisplayValue] = useState(sanitizedTarget);

  useEffect(() => {
    const fromValue = displayValue;
    const delta = sanitizedTarget - fromValue;
    if (delta === 0) {
      return undefined;
    }

    let frameId = 0;
    const startTime = performance.now();
    const animate = (now) => {
      const progress = Math.min((now - startTime) / duration, 1);
      const nextValue = fromValue + (delta * progress);
      setDisplayValue(Math.round(nextValue));
      if (progress < 1) {
        frameId = window.requestAnimationFrame(animate);
      }
    };

    frameId = window.requestAnimationFrame(animate);
    return () => {
      window.cancelAnimationFrame(frameId);
    };
  }, [sanitizedTarget]);

  return displayValue;
}

function StatCard({ label, value, accent }) {
  return (
    <div className={`rounded-2xl border p-4 ${accent}`}>
      <div className="text-xs uppercase tracking-[0.22em] text-slate-400">{label}</div>
      <div className="mt-2 text-2xl font-semibold text-white">{value}</div>
    </div>
  );
}

export default function AttackInsightsPanel({ confidence, attackSummary, fileStats }) {
  const confidenceTarget = Math.max(0, Math.min(100, Number(confidence ?? 0)));
  const confidenceAnimated = useAnimatedNumber(confidenceTarget, 600);

  const protectedAnimated = useAnimatedNumber(Number(attackSummary.files_protected ?? 0), 700);
  const encryptedAnimated = useAnimatedNumber(Number(attackSummary.files_encrypted ?? 0), 700);
  const recoveredAnimated = useAnimatedNumber(Number(attackSummary.files_recovered ?? 0), 700);

  const protectedStatsAnimated = useAnimatedNumber(Number(fileStats.files_protected ?? 0), 650);
  const recoveredStatsAnimated = useAnimatedNumber(Number(fileStats.files_recovered ?? 0), 650);

  return (
    <section className="rounded-3xl border border-slate-700/70 bg-slate-950/70 p-5 shadow-glow">
      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="text-sm uppercase tracking-[0.26em] text-orange-300/80">System Intelligence</div>
          <h2 className="mt-2 text-xl font-semibold text-white">Threat Confidence & Recovery Proof</h2>
        </div>
      </div>

      <div className="mt-5 rounded-2xl border border-orange-400/30 bg-orange-500/10 p-4">
        <div className="flex items-center justify-between gap-3 text-sm text-orange-100">
          <span>Threat Confidence: {confidenceAnimated}%</span>
          <span className="text-xs uppercase tracking-[0.2em] text-orange-200/90">Behavioral score</span>
        </div>
        <div className="mt-3 h-3 overflow-hidden rounded-full bg-slate-900/80">
          <div
            className="h-full rounded-full bg-gradient-to-r from-amber-400 via-orange-500 to-red-500 transition-all duration-700"
            style={{ width: `${confidenceAnimated}%` }}
          />
        </div>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-3">
        <StatCard
          label="Files Protected"
          value={protectedAnimated}
          accent="border-emerald-400/25 bg-emerald-500/10"
        />
        <StatCard
          label="Files Encrypted"
          value={encryptedAnimated}
          accent="border-rose-400/25 bg-rose-500/10"
        />
        <StatCard
          label="Files Recovered"
          value={recoveredAnimated}
          accent="border-sky-400/25 bg-sky-500/10"
        />
      </div>

      <div className="mt-5 rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
        <div className="text-sm uppercase tracking-[0.24em] text-slate-400">File Metrics</div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3">
            <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Files Protected</div>
            <div className="mt-1 text-xl font-semibold text-white">{protectedStatsAnimated}</div>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3">
            <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Files Recovered</div>
            <div className="mt-1 text-xl font-semibold text-white">{recoveredStatsAnimated}</div>
          </div>
        </div>
      </div>
    </section>
  );
}
