import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { AnalysisEvent } from '../../types'

interface ActivityChartProps {
  events: AnalysisEvent[]
}

interface Bucket {
  second: string
  network: number
  file: number
  crypto: number
  sql: number
  sensor: number
}

export function ActivityChart({ events }: ActivityChartProps) {
  const now = Math.floor(Date.now() / 1000)
  const buckets: Bucket[] = Array.from({ length: 60 }, (_, index) => ({
    second: `${60 - index}s`,
    network: 0,
    file: 0,
    crypto: 0,
    sql: 0,
    sensor: 0,
  }))
  events.forEach((event) => {
    const delta = now - Math.floor(event.ts_unix)
    if (delta >= 0 && delta < 60) {
      const bucket = buckets[59 - delta]
      if (event.type in bucket) {
        bucket[event.type as keyof Pick<Bucket, 'network' | 'file' | 'crypto' | 'sql' | 'sensor'>] += 1
      }
    }
  })

  return (
    <section className="rounded-md border border-line bg-white p-4">
      <h2 className="mb-3 text-base font-semibold text-ink">Activity timeline</h2>
      <div className="h-64">
        <ResponsiveContainer height="100%" width="100%">
          <BarChart data={buckets} syncId="activity">
            <CartesianGrid strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="second" hide />
            <YAxis allowDecimals={false} width={28} />
            <Tooltip />
            <Bar dataKey="network" fill="#2563eb" stackId="events" />
            <Bar dataKey="file" fill="#059669" stackId="events" />
            <Bar dataKey="crypto" fill="#d97706" stackId="events" />
            <Bar dataKey="sql" fill="#0891b2" stackId="events" />
            <Bar dataKey="sensor" fill="#dc2626" stackId="events" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  )
}
