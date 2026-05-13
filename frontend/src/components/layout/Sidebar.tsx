import { Bug, FileJson, ShieldAlert } from 'lucide-react'
import type { StaticReport } from '../../types'

interface SidebarProps {
  sessionId: string | null
  staticReport: StaticReport | null
  isAnalyzing: boolean
}

export function Sidebar({ sessionId, staticReport, isAnalyzing }: SidebarProps) {
  const manifest = staticReport?.manifest
  return (
    <aside className="min-h-screen border-r border-slate-800 bg-slate-950 px-4 py-5 text-slate-100">
      <div className="mb-6 flex items-center gap-2">
        <ShieldAlert size={22} className="text-emerald-400" />
        <div className="font-semibold">Mobile Lab</div>
      </div>
      <nav className="grid gap-2 text-sm">
        <div className="rounded-md bg-slate-900 px-3 py-3">
          <div className="text-xs uppercase text-slate-400">Session</div>
          <div className="mt-1 break-all text-slate-100">{sessionId ?? 'Waiting for APK'}</div>
        </div>
        <div className="rounded-md bg-slate-900 px-3 py-3">
          <div className="text-xs uppercase text-slate-400">Runtime</div>
          <div className="mt-1 flex items-center gap-2">
            <Bug size={16} className={isAnalyzing ? 'text-emerald-400' : 'text-slate-500'} />
            {isAnalyzing ? 'Analyzing' : 'Idle'}
          </div>
        </div>
        <div className="rounded-md bg-slate-900 px-3 py-3">
          <div className="flex items-center gap-2 text-xs uppercase text-slate-400">
            <FileJson size={15} />
            Manifest
          </div>
          <div className="mt-2 grid gap-1 text-slate-300">
            <span className="break-all">{manifest?.package ?? 'No package parsed'}</span>
            <span>targetSdk {manifest?.target_sdk ?? '-'}</span>
            <span>{staticReport?.permissions?.length ?? 0} permissions</span>
          </div>
        </div>
      </nav>
    </aside>
  )
}
