import { useEffect, useMemo, useRef, useState } from 'react'
import { emptyRisk, emptyStats, useAnalysisStore } from '../store/analysisStore'
import type { AnalysisEvent, EventStats, RiskReport, SessionSnapshot, StaticReport, WSMessage } from '../types'

interface UseWebSocketResult {
  events: AnalysisEvent[]
  stats: EventStats
  riskReport: RiskReport
  isConnected: boolean
  lastEvent: AnalysisEvent | null
}

interface ServerFrame {
  kind: 'snapshot' | 'message' | 'status'
  payload: unknown
}

const WS_BASE_URL = import.meta.env.VITE_WS_URL ?? 'ws://localhost:8000'

export function useWebSocket(sessionId: string | null, onEvent?: (event: AnalysisEvent) => void): UseWebSocketResult {
  const [isConnected, setConnected] = useState(false)
  const [lastEvent, setLastEvent] = useState<AnalysisEvent | null>(null)
  const reconnectTimer = useRef<number | null>(null)
  const socketRef = useRef<WebSocket | null>(null)
  const store = useAnalysisStore()

  useEffect(() => {
    if (!sessionId) return undefined
    let stopped = false

    const connect = () => {
      const socket = new WebSocket(`${WS_BASE_URL}/ws/${encodeURIComponent(sessionId)}?role=dashboard`)
      socketRef.current = socket
      socket.onopen = () => setConnected(true)
      socket.onclose = () => {
        setConnected(false)
        if (!stopped) {
          reconnectTimer.current = window.setTimeout(connect, 3000)
        }
      }
      socket.onmessage = (message) => {
        const frame = parseFrame(message.data)
        if (!frame) return
        if (frame.kind === 'snapshot' && isSessionSnapshot(frame.payload)) {
          store.setStaticReport(frame.payload.static_analysis)
          store.updateStats(frame.payload.stats)
          store.updateRisk(frame.payload.risk)
          frame.payload.events.slice(0, 500).reverse().forEach((event) => store.addEvent(event))
          store.setAnalyzing(frame.payload.status === 'analyzing')
          return
        }
        if (frame.kind === 'message' && isPartialMessage(frame.payload)) {
          const payload = frame.payload
          if (payload.static_analysis) {
            store.setStaticReport(payload.static_analysis)
          }
          if (isWSMessage(payload)) {
            store.addEvent(payload.event)
            store.updateStats(payload.stats)
            store.updateRisk(payload.risk)
            setLastEvent(payload.event)
            onEvent?.(payload.event)
          }
        }
      }
    }

    connect()
    return () => {
      stopped = true
      if (reconnectTimer.current !== null) {
        window.clearTimeout(reconnectTimer.current)
      }
      socketRef.current?.close()
    }
  }, [sessionId])

  return useMemo(
    () => ({
      events: store.events,
      stats: store.stats,
      riskReport: store.riskReport,
      isConnected,
      lastEvent,
    }),
    [store.events, store.stats, store.riskReport, isConnected, lastEvent],
  )
}

function parseFrame(raw: string): ServerFrame | null {
  try {
    const parsed = JSON.parse(raw) as unknown
    if (typeof parsed === 'object' && parsed !== null && 'kind' in parsed && 'payload' in parsed) {
      return parsed as ServerFrame
    }
  } catch {
    return null
  }
  return null
}

function isSessionSnapshot(value: unknown): value is SessionSnapshot {
  return typeof value === 'object' && value !== null && 'session_id' in value && 'events' in value && 'stats' in value
}

function isPartialMessage(value: unknown): value is Partial<WSMessage> & { static_analysis?: StaticReport } {
  return typeof value === 'object' && value !== null
}

function isWSMessage(value: Partial<WSMessage>): value is WSMessage {
  return Boolean(value.event && value.stats && value.risk)
}

export { emptyRisk, emptyStats }
