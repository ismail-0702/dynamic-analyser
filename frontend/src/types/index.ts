export type JsonValue = string | number | boolean | null | JsonObject | JsonValue[]
export interface JsonObject {
  [key: string]: JsonValue
}

export type EventType =
  | 'network'
  | 'file'
  | 'crypto'
  | 'sql'
  | 'permission'
  | 'ipc'
  | 'sensor'
  | 'clipboard'
  | 'location'
  | 'anti_analysis'
  | 'hook_error'
  | 'system'
  | string

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

export interface AnalysisEvent {
  type: EventType
  data: JsonObject
  timestamp: string
  ts_unix: number
  severity: Severity
  alert?: string | null
}

export interface EventStats {
  network: number
  file: number
  crypto: number
  sql: number
  permission: number
  ipc: number
  sensor: number
  clipboard: number
  location: number
  anti_analysis: number
  hook_error: number
  system: number
  alert: number
  total: number
  duration_seconds: number
}

export interface Alert {
  severity: Severity
  message: string
  event_type: string
  timestamp: string
}

export interface RiskReport {
  global_score: number
  level: RiskLevel
  dimensions: Record<'network' | 'permissions' | 'crypto' | 'behavior' | 'static', number>
  alerts: Alert[]
  alerts_count: {
    critical: number
    high: number
    medium: number
    low?: number
  }
}

export interface ManifestInfo {
  package: string
  version_name: string
  version_code: string
  min_sdk: string
  target_sdk: string
  app_name: string
  debuggable: boolean
  allow_backup: boolean
  network_security_config: boolean
  uses_cleartext_traffic: boolean
}

export interface DeclaredPermission {
  name: string
  short_name: string
  protection_level: 'normal' | 'dangerous' | 'signature' | string
  severity: Severity
}

export interface ComponentDeclaration {
  name: string
  exported: boolean
  intent_filters?: string[]
}

export interface SecretFinding {
  type: string
  value: string
  class: string
  severity: Severity
}

export interface StaticReport {
  manifest?: ManifestInfo
  permissions?: DeclaredPermission[]
  activities?: ComponentDeclaration[]
  services?: ComponentDeclaration[]
  receivers?: ComponentDeclaration[]
  secrets?: SecretFinding[]
  native_libraries?: string[]
}

export interface WSMessage {
  event: AnalysisEvent
  stats: EventStats
  risk: RiskReport
}

export interface SessionSnapshot {
  session_id: string
  apk_path: string
  created_at: string
  status: string
  static_analysis: StaticReport
  stats: EventStats
  risk: RiskReport
  events: AnalysisEvent[]
  alerts: Alert[]
}

export interface UploadResponse {
  session_id: string
  static_analysis: StaticReport
}
