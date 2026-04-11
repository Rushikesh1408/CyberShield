export default function EmergencyPanel({
  emergencyContact,
  onEmergencyContactChange,
  onSaveContact,
  onDownloadReport,
  isSavingContact,
  isDownloadingReport,
  message,
}) {
  return (
    <section className="rounded-3xl border border-slate-700/70 bg-slate-950/70 p-5 shadow-glow">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="text-sm uppercase tracking-[0.26em] text-rose-300/80">Emergency Alert System</div>
          <h2 className="mt-2 text-xl font-semibold text-white">SOS Contact & Attack Report</h2>
        </div>
      </div>

      <div className="mt-5 rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
        <div className="text-sm uppercase tracking-[0.24em] text-slate-400">Emergency Contact</div>
        <p className="mt-2 text-sm text-slate-300">
          Save the emergency email address that receives critical ransomware alert notifications.
        </p>

        <div className="mt-4 grid gap-3 md:grid-cols-[1fr_auto]">
          <input
            value={emergencyContact}
            onChange={(event) => onEmergencyContactChange(event.target.value)}
            placeholder="security-team@example.com"
            className="rounded-xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-slate-200 outline-none transition placeholder:text-slate-500 focus:border-rose-400"
          />
          <button
            type="button"
            onClick={onSaveContact}
            disabled={isSavingContact}
            className="rounded-xl border border-rose-400/40 bg-rose-500/10 px-4 py-3 text-xs font-semibold uppercase tracking-[0.18em] text-rose-200 transition hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:border-slate-700 disabled:bg-slate-900/70 disabled:text-slate-500"
          >
            {isSavingContact ? 'Saving...' : 'Save Contact'}
          </button>
        </div>
      </div>

      <div className="mt-5 rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
        <div className="text-sm uppercase tracking-[0.24em] text-slate-400">Attack Report</div>
        <p className="mt-2 text-sm text-slate-300">
          Download the latest incident report generated after a critical ransomware detection.
        </p>
        <button
          type="button"
          onClick={onDownloadReport}
          disabled={isDownloadingReport}
          className="mt-4 rounded-xl border border-sky-400/40 bg-sky-500/10 px-4 py-3 text-xs font-semibold uppercase tracking-[0.18em] text-sky-200 transition hover:bg-sky-500/20 disabled:cursor-not-allowed disabled:border-slate-700 disabled:bg-slate-900/70 disabled:text-slate-500"
        >
          {isDownloadingReport ? 'Downloading...' : 'Download Report'}
        </button>
      </div>

      {message ? (
        <div className="mt-5 rounded-xl border border-slate-700 bg-slate-950/80 p-3 text-sm text-slate-300">
          {message}
        </div>
      ) : null}
    </section>
  );
}
