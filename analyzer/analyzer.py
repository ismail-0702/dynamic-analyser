from __future__ import annotations

import asyncio
import logging
import time
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import frida
import websockets
from adb_manager import ADBManager

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s")

HOOKS_PATH = Path(__file__).resolve().parent / "frida_agent" / "hooks.js"

@dataclass
class AnalysisEvent:
    type: str
    data: dict
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ts_unix: float = field(default_factory=lambda: time.time())
    severity: str = "info"
    alert: Optional[str] = None

@dataclass
class EventStats:
    network: int = 0
    file: int = 0
    crypto: int = 0
    sql: int = 0
    permission: int = 0
    ipc: int = 0
    sensor: int = 0
    clipboard: int = 0
    location: int = 0
    anti_analysis: int = 0
    hook_error: int = 0
    system: int = 0
    alert: int = 0
    total: int = 0
    duration_seconds: float = 0.0

    def increment(self, etype: str):
        if hasattr(self, etype):
            setattr(self, etype, getattr(self, etype) + 1)
        self.total += 1

DYNAMIC_RULES = [
    # --- RÈGLES RÉSEAU ---
    ("network",  lambda e: any(x in e.get("url","") for x in ["geo.","ipify","ip-api"]), 30, "network", "high", "Géolocalisation IP"),
    ("network",  lambda e: "tracking" in e.get("url",""), 25, "network", "high", "Tracker tiers"),
    ("network",  lambda e: e.get("url","").startswith("http://"), 20, "network", "medium", "HTTP non chiffré"),
    
    # --- RÈGLES CRYPTO ---
    ("crypto",   lambda e: e.get("algorithm","") in ["MD5","DES","RC4"], 35, "crypto", "high", "Algorithme obsolète"),
    
    # --- RÈGLES PERMISSIONS ---
    ("permission",lambda e: "RECORD_AUDIO" in str(e), 30, "permissions", "high", "Accès microphone"),
    ("permission",lambda e: "ACCESS_FINE_LOCATION" in str(e), 25, "permissions", "high", "GPS précis"),
    ("permission",lambda e: "READ_SMS" in str(e), 35, "permissions", "critical", "Lecture SMS"),
    
    # --- RÈGLES DE COMPORTEMENT (FILE/PREFS) ---
    # 1. Détecte l'utilisation des SharedPreferences (ce qu'on a vu dans tes logs)
    ("file",     lambda e: "SharedPreferences" in str(e.get("path","")) or "SharedPreferences" in str(e.get("operation","")), 15, "behavior", "medium", "Stockage dans SharedPreferences"),
    
    # 2. Détecte si un mot de passe est écrit en clair (clé ou valeur)
    ("file",     lambda e: any(x in str(e).lower() for x in ["password", "pwd", "user"]), 40, "behavior", "critical", "Identifiants en clair détectés"),
    
    # 3. Détecte l'écriture de fichiers dans des zones sensibles
    ("file",     lambda e: any(x in e.get("path","").lower() for x in ["token", "secret", ".txt", ".xml"]), 30, "behavior", "high", "Fichier sensible ou log détecté"),
    
    # --- AUTRES ---
    ("sensor",   lambda e: "AudioRecord" in str(e), 40, "behavior", "critical", "Enregistrement audio"),
    ("anti_analysis", lambda e: True, 30, "behavior", "high", "Anti-analyse détectée"),
]

class RiskScorer:
    def __init__(self):
        self._scores = {"network":0.0,"permissions":0.0,"crypto":0.0,"behavior":0.0,"static":0.0}
        self.alerts = []
        self._seen = set()
        self._counts = {"critical":0,"high":0,"medium":0,"low":0}

    def process_event(self, event: AnalysisEvent):
        for i,(etype,cond,pts,dim,sev,msg) in enumerate(DYNAMIC_RULES):
            if event.type != etype:
                continue
            key = f"{i}:{etype}"
            try:
                triggered = cond(event.data)
            except:
                triggered = False
            if triggered and key not in self._seen:
                self._seen.add(key)
                self._scores[dim] = min(100, self._scores[dim] + pts)
                alert = {"severity":sev,"message":msg,"event_type":etype,"timestamp":event.timestamp}
                self.alerts.append(alert)
                self._counts[sev] = self._counts.get(sev,0) + 1
                event.severity = sev
                event.alert = msg

    def get_score(self) -> int:
        weights = {"network":0.25,"permissions":0.25,"crypto":0.20,"behavior":0.20,"static":0.10}
        return min(100, round(sum(self._scores[d]*w for d,w in weights.items())))

    def get_level(self, s):
        return "critical" if s>=75 else "high" if s>=55 else "medium" if s>=30 else "low"

    def get_report(self):
        s = self.get_score()
        return {
            "global_score": s,
            "level": self.get_level(s),
            "dimensions": {k:round(v) for k,v in self._scores.items()},
            "alerts_count": self._counts,
            "alerts": self.alerts
        }

class EventCollector:
    def __init__(self, ws_uri: str, session_id: str):
        self.ws_uri = ws_uri
        self.session_id = session_id
        self._queue: asyncio.Queue = asyncio.Queue()
        self._stats = EventStats()
        self._scorer = RiskScorer()
        self._start = time.time()
        self._loop = None

    def set_loop(self, loop):
        self._loop = loop

    def on_message(self, message, _data):
        mtype = message.get("type")
        if mtype == "error":
            log.error("Erreur Frida: %s", message.get("stack") or message.get("description"))
            return
        if mtype != "send":
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return

        etype = payload.get("type", "unknown") 
        edata = payload.get("data", payload).copy()
        if "type" in edata:
            del edata["type"]

        ts = payload.get("timestamp")
        event = AnalysisEvent(
            type=etype,
            data=edata,
            timestamp=ts if isinstance(ts, str) else datetime.now(timezone.utc).isoformat(),
        )
        if self._loop:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, event)

    async def _wait_for_backend(self, uri: str, timeout: float = 60.0) -> None:
        """Attend que uvicorn soit démarré avant d'injecter Frida."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                async with websockets.connect(uri, open_timeout=3) as ws:
                    await ws.close()
                log.info("Backend WebSocket disponible: %s", self.ws_uri)
                return
            except (OSError, websockets.InvalidURI, websockets.WebSocketException):
                log.warning(
                    "Backend injoignable (%s) — lancez: uvicorn backend.main:app --port 8000",
                    self.ws_uri,
                )
                await asyncio.sleep(3)
        raise RuntimeError(
            f"Backend WebSocket indisponible après {timeout}s. "
            f"Démarrez: uvicorn backend.main:app --reload --port 8000"
        )

    async def send_loop(self):
        # Utilisation du paramètre role=analyzer pour ws.py
        uri = f"{self.ws_uri}/ws/{self.session_id}?role=analyzer"
        await self._wait_for_backend(uri)
        while True:
            try:
                async with websockets.connect(uri) as ws:
                    log.info("WebSocket connecté au Backend")
                    while True:
                        event = await self._queue.get()
                        self._stats.increment(event.type)
                        self._stats.duration_seconds = round(time.time()-self._start, 1)
                        self._scorer.process_event(event)
                        
                        if event.alert:
                            self._stats.alert += 1

                        # CRITIQUE : Structure imbriquée pour passer la validation Pydantic (WSMessage)
                        msg = {
                            "event": {
                                "type": event.type,
                                "data": event.data,
                                "timestamp": event.timestamp,
                                "ts_unix": event.ts_unix,
                                "severity": event.severity,
                                "alert": event.alert
                            },
                            "stats": asdict(self._stats),
                            "risk": self._scorer.get_report()
                        }
                        
                        await ws.send(json.dumps(msg))
                        log.info(f"Événement envoyé au Dashboard: {event.type}")
            except Exception as e:
                log.warning("WS erreur: %s — retry 3s", e)
                await asyncio.sleep(3)

JAVA_PROBE_SCRIPT = """
rpc.exports = {
    isReady: function () { return typeof Java !== 'undefined'; }
};
"""

class DynamicAnalyzer:
    def __init__(self, apk_path, session_id, ws_uri="ws://localhost:8000",
                 adb_serial=None, frida_server_local=None, skip_install=False,
                 attach_only=True):
        self.apk_path = apk_path
        self.session_id = session_id
        self.ws_uri = ws_uri
        self.adb = ADBManager(serial=adb_serial)
        self.frida_server_local = frida_server_local
        self.skip_install = skip_install
        self.attach_only = attach_only
        self.package = None
        self._device = None
        self._session = None
        self._script = None
        self.collector = EventCollector(ws_uri, session_id)

    def _setup(self):
        self.adb.wait_for_device()
        if self.frida_server_local:
            self.adb.push_frida_server(self.frida_server_local)
        self.adb.start_frida_server()
        self.package = self.adb.get_package_name(self.apk_path)
        if not self.skip_install:
            self.adb.install_apk(self.apk_path)

    def _wait_for_java(self, timeout: float = 45.0) -> None:
        import time
        probe = self._session.create_script(JAVA_PROBE_SCRIPT)
        probe.load()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if probe.exports_sync.is_ready():
                    log.info("Runtime Java détecté")
                    probe.unload()
                    return
            except Exception as exc:
                log.debug("Probe Java: %s", exc)
            time.sleep(0.5)
        probe.unload()
        raise RuntimeError(
            "Java indisponible après attente. Vérifiez que frida-server correspond à "
            f"frida {frida.__version__} (même version sur PC et émulateur)."
        )

    def _attach_to_app(self) -> None:
        import time
        running_pid = self.adb.get_running_pid(self.package)
        if not running_pid:
            log.info("DIVA non ouverte — lancement automatique via adb am start")
            running_pid = self.adb.launch_app(self.package)
            for _ in range(12):
                if running_pid:
                    break
                time.sleep(1)
                running_pid = self.adb.get_running_pid(self.package)

        if not running_pid:
            raise RuntimeError(
                f"Impossible de lancer {self.package}. Vérifiez l'émulateur (adb devices) "
                f"et le numéro de série (--serial emulator-5554)."
            )

        try:
            self._session = self._device.attach(running_pid)
        except frida.ProcessNotFoundError as exc:
            raise RuntimeError(
                f"Processus DIVA (pid {running_pid}) introuvable — relancez l'app sur l'émulateur."
            ) from exc
        log.info("Attaché pid=%s (%s)", running_pid, self.package)

    def _check_frida_version(self) -> None:
        major = int(frida.__version__.split(".")[0])
        if major >= 17:
            raise RuntimeError(
                f"Frida {frida.__version__} installé : l'objet Java n'existe plus dans hooks.js.\n"
                "Corrigez avec :\n"
                "  pip install \"frida>=16.2.1,<17\" \"frida-tools>=12.3.0,<13\"\n"
                "  .\\scripts\\setup_frida16.ps1 emulator-5554\n"
                "(réinstalle frida-server 16.x sur l'émulateur)"
            )

    def _inject(self):
        self._check_frida_version()
        script_src = HOOKS_PATH.read_text(encoding="utf-8")
        self._device = frida.get_usb_device(timeout=15)
        log.info("Frida %s | device=%s", frida.__version__, self._device.name)

        self._attach_to_app()
        self._wait_for_java()

        self._script = self._session.create_script(script_src)
        self._script.on("message", self.collector.on_message)
        self._script.on("destroyed", lambda: log.warning("Script Frida détruit"))
        self._script.load()
        log.info("Hooks installés sur le processus DIVA")

    def _cleanup(self):
        try:
            if self._script: self._script.unload()
            if self._session: self._session.detach()
        except: pass

    async def run(self):
        loop = asyncio.get_event_loop()
        self.collector.set_loop(loop)
        await loop.run_in_executor(None, self._setup)
        # Backend doit être prêt AVANT l'injection (sinon WinError 1225)
        await self.collector._wait_for_backend(
            f"{self.ws_uri}/ws/{self.session_id}?role=analyzer"
        )
        send_task = asyncio.create_task(self.collector.send_loop())
        try:
            await loop.run_in_executor(None, self._inject)
            log.info("=== Analyse en cours ===")
            await send_task
        finally:
            self._cleanup()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("apk")
    parser.add_argument("--session", required=True)
    parser.add_argument("--ws", default="ws://localhost:8000")
    parser.add_argument("--serial")
    parser.add_argument("--skip-install", action="store_true", help="Ne pas réinstaller l'APK (recommandé)")
    parser.add_argument("--allow-spawn", action="store_true",
                        help="Autoriser frida spawn — FERME l'app (déconseillé)")
    args = parser.parse_args()
    attach_only = not args.allow_spawn  # défaut = attachement sans spawn

    analyzer = DynamicAnalyzer(
        args.apk, args.session, args.ws,
        adb_serial=args.serial,
        skip_install=args.skip_install,
        attach_only=attach_only,
    )
    asyncio.run(analyzer.run())