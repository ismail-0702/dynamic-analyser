import { Camera, MapPin, Mic, MessageSquare, ShieldCheck } from 'lucide-react'
import type { AnalysisEvent, StaticReport } from '../../types'

interface PermissionsPanelProps {
  staticReport: StaticReport | null
  events: AnalysisEvent[]
}

export function PermissionsPanel({ staticReport, events }: PermissionsPanelProps) {
  const runtimePermissions = events
    .filter((event) => event.type === 'permission')
    .flatMap((event) => {
      const permissions = event.data.permissions
      return Array.isArray(permissions) ? permissions.map(String) : []
    })

  return (
    <section className="rounded-md border border-line bg-white">
      <h2 className="border-b border-line px-4 py-3 text-base font-semibold text-ink">Permissions</h2>
      <div className="grid gap-4 p-4 lg:grid-cols-2">
        <div>
          <h3 className="mb-2 text-sm font-semibold text-slate-600">Declared in manifest</h3>
          <div className="flex flex-wrap gap-2">
            {(staticReport?.permissions ?? []).map((permission) => (
              <span
                className={`inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs ${permission.protection_level === 'dangerous' ? 'bg-red-50 text-red-700' : permission.protection_level === 'signature' ? 'bg-amber-50 text-amber-700' : 'bg-emerald-50 text-emerald-700'}`}
                key={permission.name}
              >
                {iconFor(permission.short_name)}
                {permission.short_name}
              </span>
            ))}
            {(staticReport?.permissions ?? []).length === 0 && <span className="text-sm text-slate-500">No manifest permissions parsed.</span>}
          </div>
        </div>
        <div>
          <h3 className="mb-2 text-sm font-semibold text-slate-600">Requested at runtime</h3>
          <div className="flex flex-wrap gap-2">
            {[...new Set(runtimePermissions)].map((permission) => (
              <span className="inline-flex items-center gap-1 rounded-full bg-violet-50 px-2 py-1 text-xs text-violet-700" key={permission}>
                {iconFor(permission)}
                {permission}
              </span>
            ))}
            {runtimePermissions.length === 0 && <span className="text-sm text-slate-500">No runtime permission events yet.</span>}
          </div>
        </div>
      </div>
    </section>
  )
}

function iconFor(permission: string) {
  if (permission.includes('LOCATION')) return <MapPin size={13} />
  if (permission.includes('AUDIO')) return <Mic size={13} />
  if (permission.includes('CAMERA')) return <Camera size={13} />
  if (permission.includes('SMS')) return <MessageSquare size={13} />
  return <ShieldCheck size={13} />
}
