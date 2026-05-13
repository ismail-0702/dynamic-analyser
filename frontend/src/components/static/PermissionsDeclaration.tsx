import type { StaticReport } from '../../types'

interface PermissionsDeclarationProps {
  report: StaticReport | null
}

export function PermissionsDeclaration({ report }: PermissionsDeclarationProps) {
  return (
    <section className="rounded-md border border-line bg-white">
      <h2 className="border-b border-line px-4 py-3 text-base font-semibold text-ink">Declared permissions</h2>
      <div className="grid gap-2 p-4">
        {(report?.permissions ?? []).map((permission) => (
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 py-2" key={permission.name}>
            <div>
              <div className="font-medium text-ink">{permission.short_name}</div>
              <div className="text-xs text-slate-500">{permission.name}</div>
            </div>
            <span
              className={`rounded-full px-2 py-1 text-xs ${permission.severity === 'critical' || permission.severity === 'high' ? 'bg-red-50 text-red-700' : 'bg-emerald-50 text-emerald-700'}`}
            >
              {permission.protection_level}
            </span>
          </div>
        ))}
        {(report?.permissions ?? []).length === 0 && <div className="text-sm text-slate-500">No permissions parsed.</div>}
      </div>
    </section>
  )
}
