import { AlertOctagon, AlertTriangle, Info } from 'lucide-react'
import { useState } from 'react'
import type { Alert, Severity } from '../../types'

interface AlertsPanelProps {
  alerts: Alert[]
}

const order: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const filters: Severity[] = ['critical', 'high', 'medium']

export function AlertsPanel({ alerts }: AlertsPanelProps) {
  const [enabled, setEnabled] = useState<Set<Severity>>(new Set(filters))
  const visible = alerts
    .filter((alert) => enabled.has(alert.severity))
    .sort((a, b) => order[b.severity] - order[a.severity])

  return (
    <section className="rounded-md border border-line bg-white">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
        <h2 className="text-base font-semibold text-ink">Alerts</h2>
        <div className="flex gap-2">
          {filters.map((filter) => (
            <label className="inline-flex items-center gap-1 text-xs text-slate-600" key={filter}>
              <input
                checked={enabled.has(filter)}
                onChange={() => {
                  setEnabled((current) => {
                    const next = new Set(current)
                    if (next.has(filter)) next.delete(filter)
                    else next.add(filter)
                    return next
                  })
                }}
                type="checkbox"
              />
              {filter}
            </label>
          ))}
        </div>
      </div>
      <div className="max-h-80 overflow-auto">
        {visible.map((alert, index) => (
          <article className="grid gap-1 border-b border-slate-100 px-4 py-3" key={`${alert.timestamp}-${index}`}>
            <div className="flex items-center gap-2">
              {severityIcon(alert.severity)}
              <span className="font-medium text-ink">{alert.message}</span>
            </div>
            <div className="text-xs text-slate-500">
              {alert.event_type} | {new Date(alert.timestamp).toLocaleString()}
            </div>
          </article>
        ))}
        {visible.length === 0 && <div className="px-4 py-6 text-sm text-slate-500">No selected alerts.</div>}
      </div>
    </section>
  )
}

function severityIcon(severity: Severity) {
  if (severity === 'critical') return <AlertOctagon size={16} className="text-red-700" />
  if (severity === 'high') return <AlertTriangle size={16} className="text-orange-600" />
  return <Info size={16} className="text-amber-600" />
}
