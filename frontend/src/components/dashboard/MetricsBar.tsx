import { AlertTriangle, Database, FileText, KeyRound, Network } from 'lucide-react'
import type { AnalysisEvent, EventStats } from '../../types'

interface MetricsBarProps {
  stats: EventStats
  events: AnalysisEvent[]
}

const items = [
  { key: 'network', label: 'Network', icon: Network, color: 'text-blue-600' },
  { key: 'file', label: 'Files', icon: FileText, color: 'text-emerald-600' },
  { key: 'crypto', label: 'Crypto', icon: KeyRound, color: 'text-amber-600' },
  { key: 'sql', label: 'SQL', icon: Database, color: 'text-cyan-600' },
  { key: 'alert', label: 'Alerts', icon: AlertTriangle, color: 'text-red-600' },
] as const

export function MetricsBar({ stats, events }: MetricsBarProps) {
  const now = Date.now() / 1000
  return (
    <section className="grid grid-cols-1 gap-3 md:grid-cols-5">
      {items.map((item) => {
        const Icon = item.icon
        const value = stats[item.key]
        const delta = events.filter((event) => (item.key === 'alert' ? event.alert : event.type === item.key) && now - event.ts_unix <= 60).length
        return (
          <div key={item.key} className="rounded-md border border-line bg-white p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-500">{item.label}</span>
              <Icon size={18} className={item.color} />
            </div>
            <div className="mt-2 text-3xl font-semibold text-ink">{value}</div>
            <div className="mt-1 text-xs text-slate-500">+{delta} last min.</div>
          </div>
        )
      })}
    </section>
  )
}
