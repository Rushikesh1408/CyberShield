export default function StatusCard({ title, value, caption, accent = 'blue' }) {
  const accents = {
    blue: 'from-sky-500/20 to-cyan-500/10 text-sky-100 border-sky-400/20',
    green: 'from-emerald-500/20 to-lime-500/10 text-emerald-100 border-emerald-400/20',
    amber: 'from-amber-500/20 to-orange-500/10 text-amber-100 border-amber-400/20',
    rose: 'from-rose-500/20 to-red-500/10 text-rose-100 border-rose-400/20',
  };

  return (
    <div className={`overflow-hidden rounded-2xl border bg-gradient-to-br p-5 shadow-glow ${accents[accent]}`}>
      <div className="max-w-full break-words text-xs uppercase leading-5 tracking-[0.16em] text-slate-300/80">
        {title}
      </div>
      <div className="mt-3 text-3xl font-semibold text-white">{value}</div>
      <div className="mt-2 text-sm text-slate-300">{caption}</div>
    </div>
  );
}
