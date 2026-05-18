// frontend/src/App.tsx
import { useCallback, useEffect, useRef, useState, type Dispatch, type SetStateAction } from "react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from "recharts";

// ══════════════════════════════════════════════════════════════════════════════
// TYPES
// ══════════════════════════════════════════════════════════════════════════════

interface AnalysisEvent {
  type: string;
  data: Record<string, any>;
  timestamp: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  alert?: string;
}

interface Stats {
  network: number; file: number; crypto: number; sql: number;
  permission: number; ipc: number; sensor: number; alert: number;
  total: number; duration_seconds: number;
}

interface RiskReport {
  global_score: number;
  level: "low" | "medium" | "high" | "critical";
  dimensions: Record<string, number>;
  alerts_count: { critical: number; high: number; medium: number };
}

interface StaticReport {
  manifest: Record<string, any>;
  permissions: Array<{ short_name: string; severity: string; protection_level: string }>;
  hardcoded_secrets: Array<{ type: string; value: string; severity: string; class: string }>;
  third_party_sdks: Array<{ name: string; severity: string }>;
  exported_components: Array<{ name: string; exported: boolean }>;
  summary: Record<string, number>;
  static_risk_score: number;
}

// ══════════════════════════════════════════════════════════════════════════════
// CONSTANTES VISUELLES
// ══════════════════════════════════════════════════════════════════════════════

const TYPE_META: Record<string, { color: string; bg: string; border: string; label: string; icon: string }> = {
  network:      { color:"#60a5fa", bg:"#eff6ff", border:"#bfdbfe", label:"Réseau",      icon:"⬡" },
  file:         { color:"#34d399", bg:"#ecfdf5", border:"#a7f3d0", label:"Fichier",      icon:"◈" },
  crypto:       { color:"#fbbf24", bg:"#fffbeb", border:"#fde68a", label:"Crypto",       icon:"⬟" },
  sql:          { color:"#2dd4bf", bg:"#f0fdfa", border:"#99f6e4", label:"SQL",           icon:"◉" },
  permission:   { color:"#c084fc", bg:"#faf5ff", border:"#e9d5ff", label:"Permission",   icon:"◎" },
  ipc:          { color:"#fb923c", bg:"#fff7ed", border:"#fed7aa", label:"IPC",           icon:"⬡" },
  sensor:       { color:"#f472b6", bg:"#fdf2f8", border:"#fbcfe8", label:"Capteur",      icon:"◈" },
  location:     { color:"#a78bfa", bg:"#f5f3ff", border:"#ddd6fe", label:"GPS",          icon:"◎" },
  clipboard:    { color:"#94a3b8", bg:"#f8fafc", border:"#e2e8f0", label:"Clipboard",    icon:"◇" },
  anti_analysis:{ color:"#ef4444", bg:"#fff1f2", border:"#fecdd3", label:"Anti-analyse", icon:"⬟" },
  alert:        { color:"#ef4444", bg:"#fff1f2", border:"#fecdd3", label:"Alerte",       icon:"▲" },
  hook_error:   { color:"#64748b", bg:"#f8fafc", border:"#e2e8f0", label:"Hook error",   icon:"◇" },
  system:       { color:"#6366f1", bg:"#eef2ff", border:"#c7d2fe", label:"Système",      icon:"◉" },
};

const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#22c55e", info: "#94a3b8"
};

const SEV_BG: Record<string, string> = {
  critical: "#fff1f2", high: "#fff7ed", medium: "#fffbeb", low: "#f0fdf4", info: "#f8fafc"
};

const RISK_COLOR = (score: number) =>
  score >= 75 ? "#ef4444" : score >= 50 ? "#f97316" : score >= 30 ? "#f59e0b" : "#22c55e";

// ══════════════════════════════════════════════════════════════════════════════
// HOOK WEBSOCKET
// ══════════════════════════════════════════════════════════════════════════════

const WS_BASE = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000";
const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

function applyWSMessage(
  data: Record<string, unknown>,
  setEvents: Dispatch<SetStateAction<AnalysisEvent[]>>,
  setStats: Dispatch<SetStateAction<Stats>>,
  setRisk: Dispatch<SetStateAction<RiskReport>>,
  setStatic: Dispatch<SetStateAction<StaticReport | null>>,
) {
  if (data.kind === "snapshot" && data.payload && typeof data.payload === "object") {
    const p = data.payload as Record<string, unknown>;
    if (p.static_analysis) setStatic(p.static_analysis as StaticReport);
    if (p.stats) setStats(p.stats as Stats);
    if (p.risk) setRisk(p.risk as RiskReport);
    if (Array.isArray(p.events) && p.events.length > 0) {
      setEvents([...(p.events as AnalysisEvent[])].reverse());
    }
    return;
  }

  if (data.kind === "message" && data.payload && typeof data.payload === "object") {
    const p = data.payload as Record<string, unknown>;
    if (p.event) setEvents(prev => [p.event as AnalysisEvent, ...prev].slice(0, 500));
    if (p.stats) setStats(p.stats as Stats);
    if (p.risk) setRisk(p.risk as RiskReport);
    if (p.static_analysis) setStatic(p.static_analysis as StaticReport);
    return;
  }

  if (data.kind === "status" && data.payload && typeof data.payload === "object") {
    // géré côté Dashboard via setAnalyzing — noop ici, réservé pour extension
  }
}

function useAnalysisWS(
  sessionId: string | null,
  onStatus?: (status: string) => void,
) {
  const [events, setEvents]       = useState<AnalysisEvent[]>([]);
  const [stats, setStats]         = useState<Stats>({ network:0,file:0,crypto:0,sql:0,permission:0,ipc:0,sensor:0,alert:0,total:0,duration_seconds:0 });
  const [risk, setRisk]           = useState<RiskReport>({ global_score:0, level:"low", dimensions:{}, alerts_count:{critical:0,high:0,medium:0} });
  const [staticReport, setStatic] = useState<StaticReport | null>(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (!sessionId) return;
    let stopped = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    const connect = () => {
      if (stopped) return;
      const url = `${WS_BASE}/ws/${encodeURIComponent(sessionId)}?role=dashboard`;
      socket = new WebSocket(url);

      socket.onopen = () => { if (!stopped) setConnected(true); };
      socket.onclose = () => {
        setConnected(false);
        socket = null;
        if (!stopped) reconnectTimer = setTimeout(connect, 3000);
      };
      socket.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data);
          if (data && typeof data === "object") {
            if (data.kind === "status" && data.payload?.status) {
              onStatus?.(data.payload.status as string);
            }
            applyWSMessage(data, setEvents, setStats, setRisk, setStatic);
          }
        } catch { /* ignore malformed frames */ }
      };
    };

    // Différé : évite "closed before connection" avec React StrictMode (double mount)
    const startTimer = setTimeout(connect, 0);

    return () => {
      stopped = true;
      clearTimeout(startTimer);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (socket) {
        socket.onclose = null;
        socket.close();
      }
      setConnected(false);
    };
  }, [sessionId, onStatus]);

  return { events, stats, risk, staticReport, connected };
}

// ══════════════════════════════════════════════════════════════════════════════
// COMPOSANTS UI
// ══════════════════════════════════════════════════════════════════════════════

function Badge({ severity }: { severity: string }) {
  return (
    <span style={{
      background: SEV_BG[severity], color: SEV_COLOR[severity],
      border: `1px solid ${SEV_COLOR[severity]}30`,
      borderRadius: 4, padding: "2px 7px", fontSize: 11, fontWeight: 600,
      textTransform: "uppercase", letterSpacing: "0.05em"
    }}>
      {severity}
    </span>
  );
}

function MetricCard({ label, value, sub, color }: { label:string; value:number; sub?:string; color?:string }) {
  return (
    <div style={{
      background: "#fff", borderRadius: 10, padding: "14px 16px",
      border: "1px solid #e5e7eb", flex: 1, minWidth: 100
    }}>
      <div style={{ fontSize: 12, color: "#6b7280", marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || "#111827", lineHeight: 1 }}>
        {value.toLocaleString()}
      </div>
      {sub && <div style={{ fontSize: 11, color: "#9ca3af", marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function RiskGauge({ score, level }: { score: number; level: string }) {
  const r = 52; const circ = 2 * Math.PI * r;
  const color = RISK_COLOR(score);
  const dash  = circ * (score / 100);
  return (
    <div style={{ display:"flex", alignItems:"center", gap: 20 }}>
      <div style={{ position:"relative", width:130, height:130 }}>
        <svg width="130" height="130" style={{ transform:"rotate(-90deg)" }}>
          <circle cx="65" cy="65" r={r} fill="none" stroke="#f3f4f6" strokeWidth="10"/>
          <circle cx="65" cy="65" r={r} fill="none" stroke={color} strokeWidth="10"
            strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
            style={{ transition:"stroke-dasharray 0.6s ease, stroke 0.3s" }}/>
        </svg>
        <div style={{ position:"absolute", inset:0, display:"flex", flexDirection:"column",
          alignItems:"center", justifyContent:"center" }}>
          <div style={{ fontSize: 28, fontWeight: 800, color, lineHeight: 1 }}>{score}</div>
          <div style={{ fontSize: 11, color:"#9ca3af" }}>/100</div>
        </div>
      </div>
      <div>
        <div style={{ fontSize:13, color:"#6b7280", marginBottom:8 }}>Niveau de risque</div>
        <div style={{
          background: SEV_BG[level] || "#f0fdf4",
          color: SEV_COLOR[level] || "#22c55e",
          border:`1px solid ${SEV_COLOR[level] || "#22c55e"}30`,
          borderRadius:6, padding:"4px 12px", fontWeight:700, fontSize:15,
          textTransform:"uppercase", display:"inline-block", letterSpacing:"0.08em"
        }}>
          {level}
        </div>
      </div>
    </div>
  );
}

function DimensionBars({ dimensions }: { dimensions: Record<string, number> }) {
  const labels: Record<string,string> = {
    network:"Réseau", permissions:"Permissions", crypto:"Crypto",
    behavior:"Comportement", static:"Statique"
  };
  const colors: Record<string,string> = {
    network:"#60a5fa", permissions:"#ef4444", crypto:"#fbbf24",
    behavior:"#f472b6", static:"#a78bfa"
  };
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
      {Object.entries(dimensions).map(([k, v]) => (
        <div key={k} style={{ display:"flex", alignItems:"center", gap:10 }}>
          <span style={{ fontSize:12, color:"#6b7280", width:90, flexShrink:0 }}>
            {labels[k] || k}
          </span>
          <div style={{ flex:1, height:6, background:"#f3f4f6", borderRadius:3, overflow:"hidden" }}>
            <div style={{
              height:"100%", borderRadius:3,
              width:`${Math.min(v,100)}%`,
              background: colors[k] || "#94a3b8",
              transition:"width 0.5s ease"
            }}/>
          </div>
          <span style={{ fontSize:12, color:"#9ca3af", width:28, textAlign:"right" }}>
            {Math.round(v)}
          </span>
        </div>
      ))}
    </div>
  );
}

function EventItem({ event }: { event: AnalysisEvent }) {
  const meta = TYPE_META[event.type] || TYPE_META["hook_error"];
  const time = new Date(event.timestamp).toLocaleTimeString("fr-FR");
  const detail = event.data?.url || event.data?.path || event.data?.query ||
    event.data?.algorithm || event.data?.operation || event.data?.message ||
    event.data?.tag ||
    (event.data?.key ? `key=${event.data.key}` : null) ||
    event.data?.activity ||
    JSON.stringify(event.data).slice(0, 80);
  return (
    <div style={{
      display:"flex", alignItems:"flex-start", gap:10,
      padding:"8px 10px", borderRadius:8,
      border:`1px solid ${meta.border}`,
      background: event.alert ? SEV_BG[event.severity] : meta.bg,
      animation:"fadeIn 0.25s ease", marginBottom:5,
      borderLeft: event.alert ? `3px solid ${SEV_COLOR[event.severity]}` : undefined
    }}>
      <span style={{ color:meta.color, fontSize:16, marginTop:1, flexShrink:0 }}>{meta.icon}</span>
      <div style={{ flex:1, minWidth:0 }}>
        <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:2 }}>
          <span style={{ fontSize:12, fontWeight:600, color:"#111827" }}>{meta.label}</span>
          {event.alert && <Badge severity={event.severity} />}
        </div>
        {event.alert && (
          <div style={{ fontSize:11, color:SEV_COLOR[event.severity], fontWeight:500, marginBottom:2 }}>
            ▲ {event.alert}
          </div>
        )}
        <div style={{ fontSize:11, color:"#6b7280", overflow:"hidden",
          textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
          {detail}
        </div>
      </div>
      <span style={{ fontSize:10, color:"#9ca3af", flexShrink:0 }}>{time}</span>
    </div>
  );
}

function PermissionsPanel({ permissions }: { permissions: StaticReport["permissions"] }) {
  return (
    <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
      {permissions.map((p, i) => (
        <span key={i} style={{
          display:"flex", alignItems:"center", gap:5, fontSize:11,
          padding:"4px 10px", borderRadius:20,
          background: SEV_BG[p.severity] || "#f8fafc",
          color: SEV_COLOR[p.severity] || "#6b7280",
          border:`1px solid ${SEV_COLOR[p.severity] || "#e2e8f0"}40`,
          fontWeight:500
        }}>
          {p.short_name}
        </span>
      ))}
    </div>
  );
}

function SecretsPanel({ secrets }: { secrets: StaticReport["hardcoded_secrets"] }) {
  if (!secrets?.length) return (
    <div style={{ color:"#22c55e", fontSize:13, padding:"8px 0" }}>
      ✓ Aucun secret détecté
    </div>
  );
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
      {secrets.map((s, i) => (
        <div key={i} style={{
          display:"flex", alignItems:"center", gap:10,
          padding:"8px 10px", borderRadius:8,
          background: SEV_BG[s.severity], border:`1px solid ${SEV_COLOR[s.severity]}30`
        }}>
          <Badge severity={s.severity}/>
          <div>
            <div style={{ fontSize:12, fontWeight:600, color:"#111827" }}>{s.type}</div>
            <div style={{ fontSize:11, color:"#6b7280" }}>{s.class} — <code>{s.value}</code></div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// PAGE UPLOAD
// ══════════════════════════════════════════════════════════════════════════════

function UploadPage({ onSession }: { onSession: (id: string) => void }) {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress]   = useState(0);
  const [error, setError]         = useState("");

  const upload = async (file: File) => {
    if (!file.name.endsWith(".apk")) { setError("Seuls les .apk sont acceptés"); return; }
    setUploading(true); setError(""); setProgress(10);

    const form = new FormData();
    form.append("file", file);

    try {
      setProgress(40);
      const res = await fetch(`${API_BASE}/api/apk/upload`, {
        method: "POST", body: form
      });
      setProgress(80);
      if (!res.ok) throw new Error(await res.text());
      const { session_id } = await res.json();
      setProgress(100);
      setTimeout(() => onSession(session_id), 400);
    } catch (e: any) {
      setError(e.message); setUploading(false); setProgress(0);
    }
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault(); setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) upload(file);
  };

  return (
    <div style={{
      minHeight:"100vh", background:"#f9fafb", display:"flex",
      flexDirection:"column", alignItems:"center", justifyContent:"center",
      fontFamily:"'IBM Plex Mono', monospace, sans-serif", padding: 24
    }}>
      <div style={{ marginBottom:32, textAlign:"center" }}>
        <div style={{ fontSize:36, fontWeight:800, color:"#111827", letterSpacing:"-0.03em" }}>
          APK<span style={{ color:"#6366f1" }}>Analyzer</span>
        </div>
        <div style={{ color:"#6b7280", fontSize:14, marginTop:6 }}>
          Analyse dynamique temps réel · Frida · Androguard
        </div>
      </div>

      <div
        onDragOver={e => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => document.getElementById("apk-input")!.click()}
        style={{
          width:"100%", maxWidth:480,
          border:`2px dashed ${dragging ? "#6366f1" : "#d1d5db"}`,
          borderRadius:16, padding:"48px 32px", textAlign:"center",
          background: dragging ? "#eef2ff" : "#fff",
          cursor:"pointer", transition:"all 0.2s",
          boxShadow:"0 1px 3px rgba(0,0,0,0.05)"
        }}
      >
        <div style={{ fontSize:48, marginBottom:12 }}>📦</div>
        <div style={{ fontSize:16, fontWeight:600, color:"#111827", marginBottom:6 }}>
          {uploading ? "Chargement…" : "Glisser l'APK ici"}
        </div>
        <div style={{ fontSize:13, color:"#9ca3af" }}>
          ou cliquer pour sélectionner — .apk uniquement
        </div>
        <input id="apk-input" type="file" accept=".apk" style={{ display:"none" }}
          onChange={e => { const f = e.target.files?.[0]; if (f) upload(f); }} />
      </div>

      {uploading && (
        <div style={{ width:"100%", maxWidth:480, marginTop:20 }}>
          <div style={{ height:6, background:"#e5e7eb", borderRadius:3, overflow:"hidden" }}>
            <div style={{
              height:"100%", background:"#6366f1", borderRadius:3,
              width:`${progress}%`, transition:"width 0.4s ease"
            }}/>
          </div>
          <div style={{ textAlign:"center", fontSize:12, color:"#6b7280", marginTop:8 }}>
            Upload + analyse statique en cours…
          </div>
        </div>
      )}

      {error && (
        <div style={{
          marginTop:16, padding:"10px 16px", background:"#fff1f2",
          border:"1px solid #fecdd3", borderRadius:8, color:"#991b1b", fontSize:13
        }}>
          ⚠ {error}
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// DASHBOARD PRINCIPAL
// ══════════════════════════════════════════════════════════════════════════════

function Dashboard({ sessionId, onReset }: { sessionId: string; onReset: () => void }) {
  const [analyzing, setAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState<"dynamic"|"static">("dynamic");
  const [filterType, setFilterType] = useState<string | null>(null);
  const handleWSStatus = useCallback((status: string) => {
    if (status === "analyzing") setAnalyzing(true);
    if (status === "stopped" || status === "failed") setAnalyzing(false);
  }, []);
  const { events, stats, risk, staticReport, connected } = useAnalysisWS(sessionId, handleWSStatus);

  // Timeline barres (60 dernières secondes)
  const [timeline, setTimeline] = useState<Array<{ t:number; n:number; color:string }>>([]);
  useEffect(() => {
    if (events.length === 0) return;
    const color = TYPE_META[events[0]?.type]?.color || "#6366f1";
    setTimeline(prev => [...prev.slice(-59), { t: Date.now(), n: 1, color }]);
  }, [events.length]);

  const [analysisError, setAnalysisError] = useState("");

  const startAnalysis = async () => {
    setAnalysisError("");
    try {
      const res = await fetch(`${API_BASE}/api/analysis/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: sessionId }),
      });
      if (!res.ok) {
        const errText = await res.text();
        let detail = errText;
        try { detail = JSON.parse(errText).detail ?? errText; } catch { /* raw */ }
        throw new Error(typeof detail === "string" ? detail : errText);
      }
      setAnalyzing(true);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Impossible de démarrer l'analyse";
      setAnalysisError(msg);
      setAnalyzing(false);
    }
  };

  const stopAnalysis = async () => {
    setAnalysisError("");
    try {
      const res = await fetch(`${API_BASE}/api/analysis/stop`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: sessionId }),
      });
      if (!res.ok) throw new Error(await res.text());
    } catch (e: unknown) {
      setAnalysisError(e instanceof Error ? e.message : "Impossible d'arrêter l'analyse");
    } finally {
      setAnalyzing(false);
    }
  };

  const manifest = staticReport?.manifest;
  const filteredEvents = filterType
    ? events.filter(e => e.type === filterType)
    : events;

  // ── TOPBAR ─────────────────────────────────────────────────────────────────
  return (
    <div style={{
      minHeight:"100vh", background:"#f9fafb",
      fontFamily:"'IBM Plex Mono', monospace, sans-serif", fontSize:13
    }}>
      <style>{`
        @keyframes fadeIn { from{opacity:0;transform:translateY(-4px)} to{opacity:1;transform:none} }
        @keyframes pulse  { 0%,100%{opacity:1} 50%{opacity:0.5} }
        ::-webkit-scrollbar{width:4px} ::-webkit-scrollbar-thumb{background:#d1d5db;border-radius:2px}
      `}</style>

      {/* Header */}
      <div style={{
        background:"#fff", borderBottom:"1px solid #e5e7eb",
        padding:"0 24px", display:"flex", alignItems:"center",
        justifyContent:"space-between", height:56, position:"sticky", top:0, zIndex:10
      }}>
        <div style={{ display:"flex", alignItems:"center", gap:16 }}>
          <span style={{ fontWeight:800, fontSize:18, color:"#111827", letterSpacing:"-0.02em" }}>
            APK<span style={{color:"#6366f1"}}>Analyzer</span>
          </span>
          {manifest && (
            <div style={{
              background:"#f3f4f6", borderRadius:6, padding:"3px 10px",
              fontSize:12, color:"#374151"
            }}>
              {manifest.package} · v{manifest.version_name}
            </div>
          )}
        </div>

        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          {/* Connection */}
          <div style={{ display:"flex", alignItems:"center", gap:6 }}>
            <div style={{
              width:8, height:8, borderRadius:"50%",
              background: connected ? "#22c55e" : "#ef4444",
              animation: connected ? "pulse 2s infinite" : "none"
            }}/>
            <span style={{ fontSize:12, color:"#6b7280" }}>
              {connected ? "Connecté" : "Déconnecté"}
            </span>
          </div>

          {/* Risk level */}
          {risk.global_score > 0 && (
            <div style={{
              background: SEV_BG[risk.level], color: SEV_COLOR[risk.level],
              border:`1px solid ${SEV_COLOR[risk.level]}40`,
              borderRadius:6, padding:"3px 10px", fontWeight:700, fontSize:12,
              textTransform:"uppercase"
            }}>
              ▲ {risk.level} · {risk.global_score}/100
            </div>
          )}

          {analysisError && (
            <span style={{ fontSize: 12, color: "#ef4444", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>
              {analysisError}
            </span>
          )}

          {/* Boutons */}
          {!analyzing ? (
            <button onClick={startAnalysis} title="Lance DIVA sur l'émulateur si besoin, puis injecte Frida (un seul clic)"
              style={{
              background:"#6366f1", color:"#fff", border:"none",
              borderRadius:8, padding:"7px 16px", cursor:"pointer", fontWeight:600, fontSize:13
            }}>
              ▶ Démarrer l'analyse
            </button>
          ) : (
            <button onClick={stopAnalysis} style={{
              background:"#fff", color:"#ef4444",
              border:"1px solid #fecdd3",
              borderRadius:8, padding:"7px 16px", cursor:"pointer", fontWeight:600, fontSize:13
            }}>
              ■ Arrêter
            </button>
          )}

          <button onClick={onReset} style={{
            background:"transparent", color:"#6b7280",
            border:"1px solid #e5e7eb",
            borderRadius:8, padding:"7px 12px", cursor:"pointer", fontSize:12
          }}>
            ← Nouveau
          </button>
        </div>
      </div>

      <div style={{ padding:"20px 24px", maxWidth:1440, margin:"0 auto" }}>

        {/* Tabs */}
        <div style={{ display:"flex", gap:4, marginBottom:20, background:"#f3f4f6",
          borderRadius:8, padding:4, width:"fit-content" }}>
          {(["dynamic","static"] as const).map(t => (
            <button key={t} onClick={() => setActiveTab(t)} style={{
              padding:"6px 18px", borderRadius:6, border:"none", cursor:"pointer",
              fontSize:13, fontWeight: activeTab===t ? 600 : 400,
              background: activeTab===t ? "#fff" : "transparent",
              color: activeTab===t ? "#111827" : "#6b7280",
              boxShadow: activeTab===t ? "0 1px 3px rgba(0,0,0,0.08)" : "none"
            }}>
              {t === "dynamic" ? "⚡ Dynamique" : "🔍 Statique"}
            </button>
          ))}
        </div>

        {/* ── ONGLET DYNAMIQUE ── */}
        {activeTab === "dynamic" && (
          <div style={{ display:"flex", flexDirection:"column", gap:16 }}>

            {/* Métriques */}
            <div style={{ display:"flex", gap:12, flexWrap:"wrap" }}>
              <MetricCard label="Réseau"      value={stats.network}    color="#60a5fa"/>
              <MetricCard label="Fichiers"    value={stats.file}       color="#34d399"/>
              <MetricCard label="Crypto"      value={stats.crypto}     color="#fbbf24"/>
              <MetricCard label="SQL"         value={stats.sql}        color="#2dd4bf"/>
              <MetricCard label="Permissions" value={stats.permission}  color="#c084fc"/>
              <MetricCard label="Capteurs"    value={stats.sensor}     color="#f472b6"/>
              <MetricCard label="⚠ Alertes"  value={stats.alert}      color="#ef4444"/>
              <MetricCard label="Total"       value={stats.total}/>
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>

              {/* Flux d'événements */}
              <div style={{
                background:"#fff", borderRadius:12, border:"1px solid #e5e7eb", padding:"16px 18px"
              }}>
                <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:12 }}>
                  <span style={{ fontWeight:700, color:"#111827" }}>
                    ⚡ Événements temps réel
                  </span>
                  <div style={{ display:"flex", gap:6 }}>
                    {["network","file","crypto","sql","permission","sensor"].map(t => (
                      <button key={t} onClick={() => setFilterType(filterType===t ? null : t)} style={{
                        padding:"2px 8px", borderRadius:12, border:`1px solid ${TYPE_META[t]?.border}`,
                        background: filterType===t ? TYPE_META[t]?.bg : "transparent",
                        color: TYPE_META[t]?.color, fontSize:10, cursor:"pointer", fontWeight:600
                      }}>
                        {TYPE_META[t]?.label}
                      </button>
                    ))}
                  </div>
                </div>
                <div style={{ maxHeight:400, overflowY:"auto" }}>
                  {filteredEvents.slice(0, 80).map((e, i) => (
                    <EventItem key={i} event={e}/>
                  ))}
                  {filteredEvents.length === 0 && (
                    <div style={{ textAlign:"center", color:"#9ca3af", padding:"40px 0", fontSize:13 }}>
                      {analyzing
                        ? "DIVA doit être visible sur l'émulateur — testez chaque exercice (SAVE, etc.)"
                        : "Cliquez « Démarrer l'analyse » pour lancer DIVA et capturer les événements"}
                    </div>
                  )}
                </div>
              </div>

              {/* Colonne droite */}
              <div style={{ display:"flex", flexDirection:"column", gap:16 }}>

                {/* Score de risque */}
                <div style={{
                  background:"#fff", borderRadius:12, border:"1px solid #e5e7eb", padding:"16px 18px"
                }}>
                  <div style={{ fontWeight:700, color:"#111827", marginBottom:14 }}>◎ Score de risque</div>
                  <RiskGauge score={risk.global_score} level={risk.level}/>
                  {Object.keys(risk.dimensions).length > 0 && (
                    <div style={{ marginTop:16 }}>
                      <DimensionBars dimensions={risk.dimensions}/>
                    </div>
                  )}
                </div>

                {/* Timeline */}
                <div style={{
                  background:"#fff", borderRadius:12, border:"1px solid #e5e7eb", padding:"16px 18px"
                }}>
                  <div style={{ fontWeight:700, color:"#111827", marginBottom:12 }}>
                    ◈ Activité temps réel
                  </div>
                  <div style={{ height:56, display:"flex", gap:2, alignItems:"flex-end" }}>
                    {timeline.length === 0 ? (
                      <div style={{ color:"#9ca3af", fontSize:12, margin:"auto" }}>
                        En attente d'activité…
                      </div>
                    ) : (
                      timeline.map((b, i) => (
                        <div key={i} style={{
                          flex:1, height:`${Math.min(100, 20 + b.n * 30)}%`,
                          background: b.color, borderRadius:"2px 2px 0 0",
                          opacity: 0.3 + (i / timeline.length) * 0.7,
                          minHeight:4
                        }}/>
                      ))
                    )}
                  </div>
                  <div style={{ display:"flex", justifyContent:"space-between", marginTop:4 }}>
                    <span style={{ fontSize:10, color:"#9ca3af" }}>-60s</span>
                    <span style={{ fontSize:10, color:"#9ca3af" }}>maintenant</span>
                  </div>
                </div>

                {/* Alertes récentes */}
                <div style={{
                  background:"#fff", borderRadius:12, border:"1px solid #e5e7eb", padding:"16px 18px"
                }}>
                  <div style={{ fontWeight:700, color:"#111827", marginBottom:12 }}>▲ Alertes détectées</div>
                  <div style={{ display:"flex", flexDirection:"column", gap:6, maxHeight:200, overflowY:"auto" }}>
                    {events.filter(e => e.alert).slice(0, 20).map((e, i) => (
                      <div key={i} style={{
                        display:"flex", alignItems:"center", gap:10,
                        padding:"7px 10px", borderRadius:8,
                        background: SEV_BG[e.severity],
                        border:`1px solid ${SEV_COLOR[e.severity]}30`
                      }}>
                        <Badge severity={e.severity}/>
                        <span style={{ fontSize:12, color:"#111827", flex:1 }}>{e.alert}</span>
                        <span style={{ fontSize:10, color:"#9ca3af" }}>
                          {new Date(e.timestamp).toLocaleTimeString("fr-FR")}
                        </span>
                      </div>
                    ))}
                    {events.filter(e => e.alert).length === 0 && (
                      <div style={{ color:"#9ca3af", fontSize:12, textAlign:"center", padding:"16px 0" }}>
                        Aucune alerte pour l'instant
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Distribution par type */}
            {stats.total > 0 && (
              <div style={{
                background:"#fff", borderRadius:12, border:"1px solid #e5e7eb", padding:"16px 18px"
              }}>
                <div style={{ fontWeight:700, color:"#111827", marginBottom:12 }}>
                  ◉ Distribution des événements
                </div>
                <ResponsiveContainer width="100%" height={140}>
                  <BarChart data={[
                    { name:"Réseau",      value:stats.network,    color:"#60a5fa" },
                    { name:"Fichiers",    value:stats.file,       color:"#34d399" },
                    { name:"Crypto",      value:stats.crypto,     color:"#fbbf24" },
                    { name:"SQL",         value:stats.sql,        color:"#2dd4bf" },
                    { name:"Permissions", value:stats.permission,  color:"#c084fc" },
                    { name:"IPC",         value:stats.ipc,        color:"#fb923c" },
                    { name:"Capteurs",    value:stats.sensor,     color:"#f472b6" },
                  ]}>
                    <XAxis dataKey="name" tick={{ fontSize:11 }} />
                    <YAxis tick={{ fontSize:11 }} />
                    <Tooltip/>
                    <Bar dataKey="value" radius={[4,4,0,0]}>
                      {[
                        "#60a5fa","#34d399","#fbbf24","#2dd4bf","#c084fc","#fb923c","#f472b6"
                      ].map((c, i) => <Cell key={i} fill={c}/>)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        )}

        {/* ── ONGLET STATIQUE ── */}
        {activeTab === "static" && (
          <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
            {!staticReport ? (
              <div style={{
                background:"#fff", borderRadius:12, border:"1px solid #e5e7eb",
                padding:"60px", textAlign:"center", color:"#9ca3af"
              }}>
                {analyzing || true ? "⏳ Analyse statique en cours…" : "Uploadez un APK pour voir l'analyse statique"}
              </div>
            ) : (
              <>
                {/* Manifest */}
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
                  <div style={{
                    background:"#fff", borderRadius:12, border:"1px solid #e5e7eb", padding:"16px 18px"
                  }}>
                    <div style={{ fontWeight:700, color:"#111827", marginBottom:14 }}>◈ Informations Manifest</div>
                    <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                      {[
                        ["Package",     manifest?.package],
                        ["Version",     `${manifest?.version_name} (${manifest?.version_code})`],
                        ["SDK min",     manifest?.min_sdk],
                        ["SDK cible",   manifest?.target_sdk],
                        ["Activité principale", manifest?.main_activity],
                      ].map(([k,v]) => (
                        <div key={k} style={{ display:"flex", gap:12 }}>
                          <span style={{ color:"#6b7280", width:130, flexShrink:0 }}>{k}</span>
                          <span style={{ color:"#111827", fontWeight:500 }}>{v || "N/A"}</span>
                        </div>
                      ))}
                      {[
                        ["debuggable",  manifest?.debuggable,             "Dangereux"],
                        ["allowBackup", manifest?.allow_backup,            "Risque"],
                        ["cleartext",   manifest?.uses_cleartext_traffic,  "Dangereux"],
                      ].map(([k,v,warn]) => (
                        <div key={k} style={{ display:"flex", gap:12, alignItems:"center" }}>
                          <span style={{ color:"#6b7280", width:130, flexShrink:0 }}>{k}</span>
                          <span style={{
                            color: v ? "#ef4444" : "#22c55e",
                            fontWeight:600, fontSize:12
                          }}>
                            {v ? `⚠ ${warn}` : "✓ OK"}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Summary */}
                  <div style={{
                    background:"#fff", borderRadius:12, border:"1px solid #e5e7eb", padding:"16px 18px"
                  }}>
                    <div style={{ fontWeight:700, color:"#111827", marginBottom:14 }}>◎ Résumé</div>
                    <div style={{ display:"flex", flexWrap:"wrap", gap:12 }}>
                      {Object.entries(staticReport.summary).map(([k,v]) => (
                        <div key={k} style={{
                          background:"#f9fafb", borderRadius:8, padding:"10px 14px",
                          border:"1px solid #e5e7eb", flex:"1 1 120px"
                        }}>
                          <div style={{ fontSize:22, fontWeight:700, color:"#111827" }}>{v}</div>
                          <div style={{ fontSize:11, color:"#9ca3af", marginTop:2 }}>
                            {k.replace(/_/g," ")}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Permissions */}
                <div style={{
                  background:"#fff", borderRadius:12, border:"1px solid #e5e7eb", padding:"16px 18px"
                }}>
                  <div style={{ fontWeight:700, color:"#111827", marginBottom:12 }}>
                    ◎ Permissions déclarées ({staticReport.permissions.length})
                  </div>
                  <PermissionsPanel permissions={staticReport.permissions}/>
                </div>

                {/* Secrets */}
                <div style={{
                  background:"#fff", borderRadius:12, border:"1px solid #e5e7eb", padding:"16px 18px"
                }}>
                  <div style={{ fontWeight:700, color:"#111827", marginBottom:12 }}>
                    🔑 Secrets hardcodés ({staticReport.hardcoded_secrets?.length || 0})
                  </div>
                  <SecretsPanel secrets={staticReport.hardcoded_secrets}/>
                </div>

                {/* SDKs tiers */}
                {staticReport.third_party_sdks?.length > 0 && (
                  <div style={{
                    background:"#fff", borderRadius:12, border:"1px solid #e5e7eb", padding:"16px 18px"
                  }}>
                    <div style={{ fontWeight:700, color:"#111827", marginBottom:12 }}>
                      ◈ SDKs tiers détectés
                    </div>
                    <div style={{ display:"flex", flexWrap:"wrap", gap:8 }}>
                      {staticReport.third_party_sdks.map((sdk, i) => (
                        <span key={i} style={{
                          padding:"4px 12px", borderRadius:20, fontSize:12,
                          background: SEV_BG[sdk.severity],
                          color: SEV_COLOR[sdk.severity],
                          border:`1px solid ${SEV_COLOR[sdk.severity]}30`,
                          fontWeight:500
                        }}>
                          {sdk.name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Composants exportés */}
                {staticReport.exported_components?.length > 0 && (
                  <div style={{
                    background:"#fff", borderRadius:12, border:"1px solid #e5e7eb", padding:"16px 18px"
                  }}>
                    <div style={{ fontWeight:700, color:"#111827", marginBottom:12 }}>
                      ⚠ Composants exportés ({staticReport.exported_components.length})
                    </div>
                    <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
                      {staticReport.exported_components.map((c, i) => (
                        <div key={i} style={{
                          padding:"7px 10px", borderRadius:8, fontSize:12,
                          background:"#fff7ed", border:"1px solid #fed7aa", color:"#92400e"
                        }}>
                          {c.name}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// APP ROOT
// ══════════════════════════════════════════════════════════════════════════════

import { Routes, Route, useNavigate, useParams } from 'react-router-dom'

function DashboardWrapper() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const navigate = useNavigate();
  return <Dashboard sessionId={sessionId!} onReset={() => navigate("/")} />;
}

export default function App() {
  const navigate = useNavigate();

  const handleSession = (id: string) => {
    navigate(`/session/${id}`);
  };

  return (
    <Routes>
      <Route path="/" element={<UploadPage onSession={handleSession} />} />
      <Route path="/session/:sessionId" element={<DashboardWrapper />} />
    </Routes>
  );
}
 