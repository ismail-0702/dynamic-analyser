import { Play, Square, Wifi, WifiOff } from 'lucide-react'

interface TopBarProps {
  sessionId: string | null
  isConnected: boolean
  isAnalyzing: boolean
  onStart: () => void
  onStop: () => void
}

export function TopBar({ sessionId, isConnected, isAnalyzing, onStart, onStop }: TopBarProps) {
  return (
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line bg-white px-5 py-3">
      <div>
        <h1 className="text-xl font-semibold text-ink">APK Dynamic Analyzer</h1>
        <p className="text-sm text-slate-500">{sessionId ?? 'No session selected'}</p>
      </div>
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center gap-2 rounded-md border border-line px-3 py-2 text-sm text-slate-600">
          {isConnected ? <Wifi size={16} className="text-emerald-600" /> : <WifiOff size={16} className="text-red-600" />}
          {isConnected ? 'Connected' : 'Offline'}
        </span>
        <button
          className="inline-flex items-center gap-2 rounded-md bg-brand px-3 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:bg-slate-300"
          disabled={!sessionId || isAnalyzing}
          onClick={onStart}
          title="Start dynamic analysis"
          type="button"
        >
          <Play size={16} />
          Start
        </button>
        <button
          className="inline-flex items-center gap-2 rounded-md border border-line bg-white px-3 py-2 text-sm font-medium text-ink disabled:cursor-not-allowed disabled:text-slate-400"
          disabled={!sessionId || !isAnalyzing}
          onClick={onStop}
          title="Stop dynamic analysis"
          type="button"
        >
          <Square size={16} />
          Stop
        </button>
      </div>
    </header>
  )
}
