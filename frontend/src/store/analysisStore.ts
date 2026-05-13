import { create } from 'zustand'
import type { Alert, AnalysisEvent, EventStats, RiskReport, StaticReport } from '../types'

const emptyStats: EventStats = {
  network: 0,
  file: 0,
  crypto: 0,
  sql: 0,
  permission: 0,
  ipc: 0,
  sensor: 0,
  clipboard: 0,
  location: 0,
  anti_analysis: 0,
  hook_error: 0,
  system: 0,
  alert: 0,
  total: 0,
  duration_seconds: 0,
}

const emptyRisk: RiskReport = {
  global_score: 0,
  level: 'low',
  dimensions: {
    network: 0,
    permissions: 0,
    crypto: 0,
    behavior: 0,
    static: 0,
  },
  alerts: [],
  alerts_count: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  },
}

interface AnalysisState {
  sessionId: string | null
  apkInfo: StaticReport['manifest'] | null
  staticReport: StaticReport | null
  events: AnalysisEvent[]
  stats: EventStats
  riskReport: RiskReport
  alerts: Alert[]
  isAnalyzing: boolean
  setSession: (id: string) => void
  setStaticReport: (report: StaticReport) => void
  addEvent: (event: AnalysisEvent) => void
  updateStats: (stats: EventStats) => void
  updateRisk: (risk: RiskReport) => void
  setAnalyzing: (value: boolean) => void
  reset: () => void
}

export const useAnalysisStore = create<AnalysisState>((set) => ({
  sessionId: null,
  apkInfo: null,
  staticReport: null,
  events: [],
  stats: emptyStats,
  riskReport: emptyRisk,
  alerts: [],
  isAnalyzing: false,
  setSession: (id) => set({ sessionId: id }),
  setStaticReport: (report) => set({ staticReport: report, apkInfo: report.manifest ?? null }),
  addEvent: (event) =>
    set((state) => ({
      events: [event, ...state.events].slice(0, 500),
      alerts: event.alert
        ? [
            {
              severity: event.severity,
              message: event.alert,
              event_type: String(event.type),
              timestamp: event.timestamp,
            },
            ...state.alerts,
          ].slice(0, 200)
        : state.alerts,
    })),
  updateStats: (stats) => set({ stats }),
  updateRisk: (risk) =>
    set((state) => ({
      riskReport: risk,
      alerts: risk.alerts.length > 0 ? risk.alerts : state.alerts,
    })),
  setAnalyzing: (value) => set({ isAnalyzing: value }),
  reset: () =>
    set({
      sessionId: null,
      apkInfo: null,
      staticReport: null,
      events: [],
      stats: emptyStats,
      riskReport: emptyRisk,
      alerts: [],
      isAnalyzing: false,
    }),
}))

export { emptyRisk, emptyStats }
