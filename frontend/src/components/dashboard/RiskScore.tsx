import type { RiskReport } from '../../types'

interface RiskScoreProps {
  risk: RiskReport
}

export function RiskScore({ risk }: RiskScoreProps) {
  const radius = 46
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (risk.global_score / 100) * circumference
  const color = risk.global_score < 40 ? '#16a34a' : risk.global_score < 70 ? '#f59e0b' : '#dc2626'

  return (
    <section className="rounded-md border border-line bg-white p-4">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="relative h-32 w-32">
          <svg className="-rotate-90" height="128" viewBox="0 0 128 128" width="128">
            <circle cx="64" cy="64" fill="none" r={radius} stroke="#e2e8f0" strokeWidth="12" />
            <circle
              cx="64"
              cy="64"
              fill="none"
              r={radius}
              stroke={color}
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              strokeLinecap="round"
              strokeWidth="12"
            />
          </svg>
          <div className="absolute inset-0 grid place-items-center text-center">
            <div>
              <div className="text-3xl font-semibold text-ink">{risk.global_score}</div>
              <div className="text-xs uppercase text-slate-500">{risk.level}</div>
            </div>
          </div>
        </div>
        <div className="min-w-[220px] flex-1">
          <h2 className="mb-3 text-base font-semibold text-ink">Risk score</h2>
          <div className="grid gap-2">
            {Object.entries(risk.dimensions).map(([name, value]) => (
              <div key={name}>
                <div className="mb-1 flex justify-between text-xs text-slate-500">
                  <span>{name}</span>
                  <span>{value}</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-slate-200">
                  <div className="h-full rounded-full bg-brand" style={{ width: `${Math.min(value, 100)}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
