import type { AnalysisEvent } from '../../types'

interface NetworkGraphProps {
  events: AnalysisEvent[]
}

interface NetworkRow {
  method: string
  url: string
  count: number
  lastSeen: string
  risk: 'low' | 'medium' | 'high'
}

export function NetworkGraph({ events }: NetworkGraphProps) {
  const rows = buildRows(events)
  return (
    <section className="rounded-md border border-line bg-white">
      <h2 className="border-b border-line px-4 py-3 text-base font-semibold text-ink">Network connections</h2>
      <div className="overflow-auto">
        <table className="w-full min-w-[620px] text-left text-sm">
          <thead className="bg-slate-50 text-xs uppercase text-slate-500">
            <tr>
              <th className="px-4 py-2">Method</th>
              <th className="px-4 py-2">URL</th>
              <th className="px-4 py-2">Calls</th>
              <th className="px-4 py-2">Last seen</th>
              <th className="px-4 py-2">Risk</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr className="border-t border-slate-100" key={`${row.method}-${row.url}`}>
                <td className="px-4 py-2">
                  <span className={`rounded px-2 py-1 text-xs ${row.method === 'POST' ? 'bg-emerald-50 text-emerald-700' : 'bg-blue-50 text-blue-700'}`}>
                    {row.method}
                  </span>
                </td>
                <td className="max-w-[380px] truncate px-4 py-2 text-slate-700">{row.url}</td>
                <td className="px-4 py-2">{row.count}</td>
                <td className="px-4 py-2 text-slate-500">{row.lastSeen}</td>
                <td className="px-4 py-2">
                  <span className={`rounded px-2 py-1 text-xs ${row.risk === 'high' ? 'bg-red-50 text-red-700' : row.risk === 'medium' ? 'bg-amber-50 text-amber-700' : 'bg-emerald-50 text-emerald-700'}`}>
                    {row.risk}
                  </span>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td className="px-4 py-6 text-slate-500" colSpan={5}>
                  No network activity yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function buildRows(events: AnalysisEvent[]): NetworkRow[] {
  const grouped = new Map<string, NetworkRow>()
  events
    .filter((event) => event.type === 'network')
    .forEach((event) => {
      const url = String(event.data.url ?? '')
      const method = String(event.data.method ?? 'GET')
      const key = `${method}:${url}`
      const row = grouped.get(key)
      const risk: NetworkRow['risk'] = url.startsWith('http://') ? 'medium' : url.includes('tracking') || url.includes('geo.') ? 'high' : 'low'
      if (row) {
        row.count += 1
        row.lastSeen = new Date(event.timestamp).toLocaleTimeString()
      } else {
        grouped.set(key, { method, url, count: 1, lastSeen: new Date(event.timestamp).toLocaleTimeString(), risk })
      }
    })
  return [...grouped.values()].sort((a, b) => b.count - a.count)
}
