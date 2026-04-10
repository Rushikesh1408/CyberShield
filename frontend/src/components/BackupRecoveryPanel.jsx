import { useEffect, useState } from 'react';

function formatTimestamp(timestamp) {
  if (!timestamp) {
    return 'No backups yet';
  }

  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return timestamp;
  }

  return date.toLocaleString([], {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export default function BackupRecoveryPanel({
  backupStatus,
  onRunBackup,
  onRecoverFile,
  isRunningBackup,
  isRecovering,
  message,
}) {
  const [filePathInput, setFilePathInput] = useState('');

  useEffect(() => {
    if (!filePathInput && Array.isArray(backupStatus.recent_files) && backupStatus.recent_files.length > 0) {
      setFilePathInput(backupStatus.recent_files[0]);
    }
  }, [backupStatus.recent_files, filePathInput]);

  const handleRecover = () => {
    const trimmed = filePathInput.trim();
    if (!trimmed) {
      return;
    }
    onRecoverFile(trimmed);
  };

  return (
    <section className="rounded-3xl border border-slate-700/70 bg-slate-950/70 p-5 shadow-glow">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="text-sm uppercase tracking-[0.26em] text-emerald-300/80">Versioned Snapshot System</div>
          <h2 className="mt-2 text-xl font-semibold text-white">Automatic System Recovery</h2>
        </div>
        <button
          type="button"
          onClick={onRunBackup}
          disabled={isRunningBackup}
          className="rounded-xl border border-emerald-400/40 bg-emerald-500/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-emerald-200 transition hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:border-slate-700 disabled:bg-slate-900/70 disabled:text-slate-500"
        >
          {isRunningBackup ? 'Running...' : 'Run Snapshot Now'}
        </button>
      </div>

      <div className="mt-5 rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
        <div className="text-sm uppercase tracking-[0.24em] text-slate-400">Backup Status</div>
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3">
            <div className="text-xs uppercase tracking-[0.2em] text-slate-500">State</div>
            <div
              className={`mt-2 text-lg font-semibold ${
                backupStatus.status === 'Active' ? 'text-emerald-300' : 'text-rose-300'
              }`}
            >
              {backupStatus.status}
            </div>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3">
            <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Files Secured</div>
            <div className="mt-2 text-lg font-semibold text-white">{backupStatus.files_secured}</div>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3">
            <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Last Backup</div>
            <div className="mt-2 text-sm font-medium text-slate-200">
              {formatTimestamp(backupStatus.last_backup_time)}
            </div>
          </div>
        </div>
      </div>

      <div className="mt-5 rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
        <div className="text-sm uppercase tracking-[0.24em] text-slate-400">Recover File</div>
        <p className="mt-2 text-sm text-slate-300">
          Select a secured file or paste a full path, then restore it using Automatic System Recovery.
        </p>

        <div className="mt-4 grid gap-3 md:grid-cols-[1fr_auto]">
          <input
            value={filePathInput}
            onChange={(event) => setFilePathInput(event.target.value)}
            placeholder="C:\\Users\\...\\important.docx"
            className="rounded-xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-slate-200 outline-none transition placeholder:text-slate-500 focus:border-sky-400"
          />
          <button
            type="button"
            onClick={handleRecover}
            disabled={isRecovering || !filePathInput.trim()}
            className="rounded-xl border border-sky-400/40 bg-sky-500/10 px-4 py-3 text-xs font-semibold uppercase tracking-[0.18em] text-sky-200 transition hover:bg-sky-500/20 disabled:cursor-not-allowed disabled:border-slate-700 disabled:bg-slate-900/70 disabled:text-slate-500"
          >
            {isRecovering ? 'Recovering...' : 'Recover File'}
          </button>
        </div>

        {Array.isArray(backupStatus.recent_files) && backupStatus.recent_files.length > 0 ? (
          <div className="mt-4">
            <div className="mb-2 text-xs uppercase tracking-[0.2em] text-slate-500">Recent Secured Files</div>
            <div className="flex flex-wrap gap-2">
              {backupStatus.recent_files.slice(0, 6).map((pathValue) => (
                <button
                  key={pathValue}
                  type="button"
                  onClick={() => setFilePathInput(pathValue)}
                  className="rounded-full border border-slate-700 bg-slate-950/70 px-3 py-1 text-xs text-slate-300 transition hover:border-sky-400 hover:text-sky-300"
                >
                  {pathValue}
                </button>
              ))}
            </div>
          </div>
        ) : null}

        {message ? (
          <div className="mt-4 rounded-xl border border-slate-700 bg-slate-950/80 p-3 text-sm text-slate-300">
            {message}
          </div>
        ) : null}
      </div>
    </section>
  );
}
