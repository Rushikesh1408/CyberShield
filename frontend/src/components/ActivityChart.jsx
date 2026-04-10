import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

const tooltipStyle = {
  background: 'rgba(15, 23, 42, 0.96)',
  border: '1px solid rgba(148, 163, 184, 0.22)',
  borderRadius: 14,
  color: '#e2e8f0',
};

export default function ActivityChart({ data }) {
  return (
    <div className="rounded-3xl border border-slate-700/70 bg-slate-950/70 p-5 shadow-glow">
      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="text-sm uppercase tracking-[0.26em] text-sky-300/80">
            Real-Time Activity
          </div>
          <h2 className="mt-2 text-xl font-semibold text-white">Files per second</h2>
        </div>
        <div className="rounded-full border border-slate-700 bg-slate-900/80 px-3 py-1 text-xs text-slate-300">
          Polling every 2 seconds
        </div>
      </div>
      <div className="mt-5 h-72">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="activityFill" x1="0" x2="0" y1="0" y2="1">
                <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.45} />
                <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.14)" />
            <XAxis dataKey="label" stroke="#94a3b8" tickLine={false} axisLine={false} />
            <YAxis stroke="#94a3b8" tickLine={false} axisLine={false} width={36} />
            <Tooltip contentStyle={tooltipStyle} />
            <Area
              type="monotone"
              dataKey="files_per_second"
              stroke="#38bdf8"
              strokeWidth={3}
              fill="url(#activityFill)"
              dot={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
