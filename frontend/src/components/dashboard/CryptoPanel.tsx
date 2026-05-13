import type { AnalysisEvent } from '../../types'

interface CryptoPanelProps {
  events: AnalysisEvent[]
}

const weakAlgorithms = ['MD5', 'DES', 'RC4']

export function CryptoPanel({ events }: CryptoPanelProps) {
  const counts = new Map<string, number>()
  events
    .filter((event) => event.type === 'crypto')
    .forEach((event) => {
      const algorithm = String(event.data.algorithm ?? 'unknown')
      counts.set(algorithm, (counts.get(algorithm) ?? 0) + 1)
    })
  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1])
  const max = Math.max(1, ...rows.map(([, count]) => count))
  return (
    <section className="rounded-md border border-line bg-white">
      <h2 className="border-b border-line px-4 py-3 text-base font-semibold text-ink">Crypto algorithms</h2>
      <div className="grid gap-3 p-4">
        {rows.map(([algorithm, count]) => {
          const weak = weakAlgorithms.some((item) => algorithm.toUpperCase().includes(item))
          return (
            <div key={algorithm}>
              <div className="mb-1 flex justify-between text-sm">
                <span className={weak ? 'font-semibold text-red-700' : 'text-slate-700'}>{algorithm}</span>
                <span className="text-slate-500">{count}</span>
              </div>
              <div className="h-2 rounded-full bg-slate-200">
                <div className={`h-2 rounded-full ${weak ? 'bg-red-600' : 'bg-brand'}`} style={{ width: `${(count / max) * 100}%` }} />
              </div>
            </div>
          )
        })}
        {rows.length === 0 && <div className="text-sm text-slate-500">No crypto activity yet.</div>}
      </div>
    </section>
  )
}
