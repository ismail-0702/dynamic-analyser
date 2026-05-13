import type { StaticReport } from '../../types'

interface ManifestViewerProps {
  report: StaticReport | null
}

export function ManifestViewer({ report }: ManifestViewerProps) {
  const manifest = report?.manifest
  return (
    <section className="rounded-md border border-line bg-white">
      <h2 className="border-b border-line px-4 py-3 text-base font-semibold text-ink">Manifest viewer</h2>
      <div className="grid gap-4 p-4 lg:grid-cols-2">
        <div>
          <h3 className="mb-2 text-sm font-semibold text-slate-600">App info</h3>
          <dl className="grid gap-2 text-sm">
            <Row label="Package" value={manifest?.package ?? '-'} />
            <Row label="Version" value={manifest?.version_name ?? '-'} />
            <Row label="Min SDK" value={manifest?.min_sdk ?? '-'} />
            <Row label="Target SDK" value={manifest?.target_sdk ?? '-'} />
            <Row danger={manifest?.debuggable} label="Debuggable" value={String(Boolean(manifest?.debuggable))} />
            <Row danger={manifest?.allow_backup} label="Allow backup" value={String(Boolean(manifest?.allow_backup))} />
            <Row danger={manifest?.uses_cleartext_traffic} label="Cleartext traffic" value={String(Boolean(manifest?.uses_cleartext_traffic))} />
          </dl>
        </div>
        <div className="grid gap-3 text-sm">
          <ComponentList items={report?.activities ?? []} title="Activities" />
          <ComponentList items={report?.services ?? []} title="Services" />
          <ComponentList items={report?.receivers ?? []} title="Receivers" />
        </div>
      </div>
    </section>
  )
}

function Row({ label, value, danger = false }: { label: string; value: string; danger?: boolean }) {
  return (
    <div className="grid grid-cols-[130px_1fr] gap-3">
      <dt className="text-slate-500">{label}</dt>
      <dd className={danger ? 'font-semibold text-red-700' : 'break-all text-ink'}>{value}</dd>
    </div>
  )
}

function ComponentList({ title, items }: { title: string; items: { name: string; exported: boolean }[] }) {
  return (
    <div>
      <h3 className="mb-1 font-semibold text-slate-600">{title}</h3>
      <div className="max-h-32 overflow-auto rounded-md border border-slate-100">
        {items.map((item) => (
          <div className="flex justify-between gap-2 border-b border-slate-100 px-2 py-1" key={item.name}>
            <span className="truncate">{item.name}</span>
            <span className={item.exported ? 'text-red-700' : 'text-emerald-700'}>{item.exported ? 'exported' : 'private'}</span>
          </div>
        ))}
        {items.length === 0 && <div className="px-2 py-2 text-slate-500">None parsed.</div>}
      </div>
    </div>
  )
}
