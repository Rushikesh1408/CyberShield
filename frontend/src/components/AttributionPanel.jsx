function shortHash(value) {
  const hash = String(value || '');
  if (!hash) {
    return 'n/a';
  }
  if (hash.length <= 16) {
    return hash;
  }
  return `${hash.slice(0, 10)}...${hash.slice(-6)}`;
}

export default function AttributionPanel({ signatureData, networkData, reportData }) {
  const latestSignature = signatureData?.latest ?? {};
  const correlation = signatureData?.correlation ?? { matched: false, matches: [] };
  const recentConnections = Array.isArray(networkData?.recent) ? networkData.recent : [];
  const wallets = Array.isArray(reportData?.wallets) ? reportData.wallets : [];
  const processTree = Array.isArray(reportData?.process_tree) ? reportData.process_tree : [];
  const reports = Array.isArray(reportData?.reports) ? reportData.reports : [];

  return (
    <section className="rounded-3xl border border-slate-700/70 bg-slate-950/70 p-5 shadow-glow">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-sm uppercase tracking-[0.26em] text-violet-300/80">Attribution Intelligence</div>
          <h2 className="mt-2 text-xl font-semibold text-white">Signature, Network, and Process Origin</h2>
        </div>
        <div className="rounded-xl border border-slate-700 bg-slate-900/70 px-3 py-2 text-xs text-slate-300">
          Reports: {reports.length}
        </div>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-2xl border border-violet-400/30 bg-violet-500/10 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-violet-200">Latest Signature</div>
          <div className="mt-2 text-sm font-semibold text-white">{shortHash(latestSignature.signature_id)}</div>
        </div>
        <div className="rounded-2xl border border-sky-400/30 bg-sky-500/10 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-sky-200">Correlation Matches</div>
          <div className="mt-2 text-2xl font-semibold text-white">
            {Array.isArray(correlation.matches) ? correlation.matches.length : 0}
          </div>
        </div>
        <div className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-amber-200">Wallet Indicators</div>
          <div className="mt-2 text-2xl font-semibold text-white">{wallets.length}</div>
        </div>
        <div className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-4">
          <div className="text-xs uppercase tracking-[0.2em] text-rose-200">Network Events</div>
          <div className="mt-2 text-2xl font-semibold text-white">{recentConnections.length}</div>
        </div>
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="text-sm uppercase tracking-[0.2em] text-slate-400">Process Tree</div>
          <div className="mt-3 max-h-44 space-y-2 overflow-y-auto">
            {processTree.length === 0 ? (
              <div className="text-sm text-slate-500">No process attribution captured yet.</div>
            ) : (
              processTree.map((node) => (
                <div
                  key={`${node.pid}-${node.parent_pid}`}
                  className="rounded-xl border border-slate-800 bg-slate-950/80 px-3 py-2 text-xs text-slate-300"
                >
                  PID {node.pid} | PPID {node.parent_pid} | {node.name || 'unknown'}
                </div>
              ))
            )}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="text-sm uppercase tracking-[0.2em] text-slate-400">Recent Network Connections</div>
          <div className="mt-3 max-h-44 space-y-2 overflow-y-auto">
            {recentConnections.length === 0 ? (
              <div className="text-sm text-slate-500">No outbound telemetry for suspicious process.</div>
            ) : (
              recentConnections.map((event, index) => (
                <div
                  key={`${event.pid}-${event.remote_ip}-${event.remote_port}-${index}`}
                  className="rounded-xl border border-slate-800 bg-slate-950/80 px-3 py-2 text-xs text-slate-300"
                >
                  {event.process_name || 'unknown'} | {event.remote_ip || 'n/a'}:{event.remote_port || 0} | {event.status}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
