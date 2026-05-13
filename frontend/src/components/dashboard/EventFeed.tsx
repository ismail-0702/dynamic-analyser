import { Pause, Play, ShieldAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import type { AnalysisEvent } from '../../types'

interface EventFeedProps {
  events: AnalysisEvent[]
}

const eventTypes = ['network', 'file', 'crypto', 'sql', 'permission', 'ipc', 'sensor', 'clipboard', 'anti_analysis', 'hook_error']

const typeClasses: Record<string, string> = {
  network: 'bg-blue-50 text-blue-700',
  file: 'bg-emerald-50 text-emerald-700',
  crypto: 'bg-amber-50 text-amber-700',
  sql: 'bg-cyan-50 text-cyan-700',
  permission: 'bg-violet-50 text-violet-700',
  alert: 'bg-red-50 text-red-700',
  hook_error: 'bg-red-50 text-red-700',
}

export function EventFeed({ events }: EventFeedProps) {
  const [paused, setPaused] = useState(false)
  const [enabled, setEnabled] = useState<Set<string>>(new Set(eventTypes))
  const visible = useMemo(
    () => (paused ? events : events.filter((event) => enabled.has(String(event.type))).slice(0, 50)),
    [enabled, events, paused],
  )

  return (
    <section className="rounded-md border border-line bg-white">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
        <h2 className="text-base font-semibold text-ink">Live event feed</h2>
        <button
          className="inline-flex items-center gap-2 rounded-md border border-line px-2 py-1 text-sm"
          onClick={() => setPaused((value) => !value)}
          type="button"
        >
          {paused ? <Play size={15} /> : <Pause size={15} />}
          {paused ? 'Resume' : 'Pause'}
        </button>
      </div>
      <div className="flex flex-wrap gap-2 border-b border-line px-4 py-2">
        {eventTypes.map((type) => (
          <label key={type} className="inline-flex items-center gap-1 text-xs text-slate-600">
            <input
              checked={enabled.has(type)}
              onChange={() => {
                setEnabled((current) => {
                  const next = new Set(current)
                  if (next.has(type)) next.delete(type)
                  else next.add(type)
                  return next
                })
              }}
              type="checkbox"
            />
            {type}
          </label>
        ))}
      </div>
      <div className="max-h-[520px] overflow-auto">
        {visible.length === 0 ? (
          <div className="px-4 py-6 text-sm text-slate-500">No matching events yet.</div>
        ) : (
          visible.map((event, index) => <EventRow event={event} key={`${event.ts_unix}-${index}`} />)
        )}
      </div>
    </section>
  )
}

function EventRow({ event }: { event: AnalysisEvent }) {
  const badge = event.alert ? 'alert' : String(event.type)
  return (
    <article className="event-enter grid gap-2 border-b border-slate-100 px-4 py-3">
      <div className="flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <ShieldAlert size={15} className="text-slate-400" />
          <span className={`rounded-full px-2 py-1 text-xs ${typeClasses[badge] ?? 'bg-slate-100 text-slate-700'}`}>{event.type}</span>
          <span className="truncate text-sm text-slate-600">{detail(event)}</span>
        </div>
        <time className="shrink-0 text-xs text-slate-400">{new Date(event.timestamp).toLocaleTimeString()}</time>
      </div>
      {event.alert && <div className="rounded-md bg-red-50 px-2 py-1 text-xs text-red-700">{event.alert}</div>}
    </article>
  )
}

function detail(event: AnalysisEvent): string {
  const data = event.data
  const value = data.url ?? data.path ?? data.query ?? data.algorithm ?? data.operation ?? data.message ?? JSON.stringify(data)
  return String(value).slice(0, 150)
}
