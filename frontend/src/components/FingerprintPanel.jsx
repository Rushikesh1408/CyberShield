export default function FingerprintPanel({ fingerprints }) {
  return (
    <div className="rounded-3xl border border-slate-700/70 bg-slate-950/70 p-5 shadow-glow">
      <div>
        <div className="text-sm uppercase tracking-[0.26em] text-emerald-300/80">
          Attack Fingerprints
        </div>
        <h2 className="mt-2 text-xl font-semibold text-white">Stored similarity patterns</h2>
      </div>
      <div className="mt-5 max-h-[34rem] space-y-3 overflow-y-auto pr-1">
        {fingerprints.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-700 bg-slate-900/50 p-5 text-sm text-slate-400">
            No fingerprints stored yet.
          </div>
        ) : (
          fingerprints.map((item, index) => (
            <div key={`${item.signature_hash}-${index}`} className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="font-semibold text-white">{item.process_name}</div>
                <div className="rounded-full border border-emerald-400/20 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-100">
                  {item.occurrences} hits
                </div>
              </div>
              <div className="mt-2 grid grid-cols-2 gap-2 text-sm text-slate-300 md:grid-cols-4">
                <div>Ext: {item.file_extension}</div>
                <div>Mods: {item.modification_rate}</div>
                <div>Access: {item.access_rate}</div>
                <div>CPU: {item.cpu_spike}%</div>
              </div>
              <div className="mt-3 text-xs text-slate-500">{item.timestamp}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
