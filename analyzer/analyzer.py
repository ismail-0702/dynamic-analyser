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
    ("file",     lambda e: e.get("path") == "SharedPreferences", 15, "behavior", "medium", "Stockage dans SharedPreferences"),
    
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
        if message.get("type") != "send":
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return

        etype = payload.get("type", "unknown") 
        edata = payload.get("data", payload).copy()
        if "type" in edata:
            del edata["type"]

        event = AnalysisEvent(type=etype, data=edata)
        if self._loop:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, event)

    async def send_loop(self):
        # Utilisation du paramètre role=analyzer pour ws.py
        uri = f"{self.ws_uri}/ws/{self.session_id}?role=analyzer"
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

class DynamicAnalyzer:
    def __init__(self, apk_path, session_id, ws_uri="ws://localhost:8000",
                 adb_serial=None, frida_server_local=None, skip_install=False):
        self.apk_path = apk_path
        self.session_id = session_id
        self.ws_uri = ws_uri
        self.adb = ADBManager(serial=adb_serial)
        self.frida_server_local = frida_server_local
        self.skip_install = skip_install
        self.package = None
        self._device = None
        self._session = None
        self._script = None
        self.collector = EventCollector(ws_uri, session_id)

    def _setup(self):
        self.adb.wait_for_device()
        self.adb.start_frida_server()
        self.package = self.adb.get_package_name(self.apk_path)
        if not self.skip_install:
            self.adb.install_apk(self.apk_path)

    def _inject(self):
        import subprocess
        self._device = frida.get_usb_device(timeout=15)
        
        # On force la détection du PID par ADB pour être sûr
        out = subprocess.check_output(["adb", "-s", self.adb.serial or "", "shell", "pidof", self.package])
        target_pid = int(out.strip())
        
        self._session = self._device.attach(target_pid)
        script_src = HOOKS_PATH.read_text(encoding="utf-8")
        self._script = self._session.create_script(script_src)
        self._script.on("message", self.collector.on_message)
        self._script.load()
        import time
        time.sleep(1)
        # Envoyer le signal pour démarrer les hooks
        
        log.info("Hooks seront installés automatiquement après 2s")

    def _cleanup(self):
        try:
            if self._script: self._script.unload()
            if self._session: self._session.detach()
        except: pass

    async def run(self):
        loop = asyncio.get_event_loop()
        self.collector.set_loop(loop)
        await loop.run_in_executor(None, self._setup)
        await loop.run_in_executor(None, self._inject)
        log.info("=== Analyse en cours ===")
        await self.collector.send_loop()

    async def _on_message(self, message, data):
        """Cette méthode est appelée par Frida à chaque hook"""
        if message['type'] == 'send':
            payload = message['payload']
            
            # 1. On donne l'info au RiskScorer (Classe n°5) pour mettre à jour les points
            self.scorer.process_event(payload)
            
            # 2. On récupère le rapport global calculé
            report = self.scorer.get_report()
            
            # 3. ON INSÈRE TON CODE ICI :
            # On envoie les données formatées au AnalyzerWebSocketClient (Classe n°9)
            await self.ws_client.send({
                "session_id": self.session_id,
                "type": "update",
                "stats": report["dimensions"],    # Met à jour les compteurs (Fichiers, Réseau, etc.)
                "alerts": report["alerts"],       # Envoie la liste des alertes
                "global_score": report["global_score"] # Met à jour la jauge de risque
            })
# Pour le lancement direct via main.py
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("apk")
    parser.add_argument("--session", required=True)
    parser.add_argument("--ws", default="ws://localhost:8000")
    parser.add_argument("--serial")
    parser.add_argument("--skip-install", action="store_true")
    args = parser.parse_args()
    
    analyzer = DynamicAnalyzer(args.apk, args.session, args.ws, adb_serial=args.serial, skip_install=args.skip_install)
    asyncio.run(analyzer.run())