"""In-memory analysis session manager."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.models.event import Alert, AnalysisEvent, EventStats, RiskReport
from backend.models.session import SessionModel

MAX_EVENTS = int(os.environ.get("MAX_EVENTS_BUFFER", "1000"))
PROJECT_ROOT = Path(__file__).resolve().parents[2]
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", PROJECT_ROOT / "uploads"))


@dataclass
class SessionRuntime:
    """Internal session state including subprocess handles."""

    model: SessionModel
    process: subprocess.Popen[str] | None = None
    events: deque[AnalysisEvent] = field(default_factory=lambda: deque(maxlen=MAX_EVENTS))


class SessionManager:
    """Singleton-style manager for all in-memory analysis sessions."""

    def __init__(self) -> None:
        """Initialize the session registry."""
        self.sessions: dict[str, SessionRuntime] = {}

    def create_session(self, apk_path: str) -> SessionModel:
        """Create and store a new analysis session."""
        session_id = str(uuid.uuid4())
        model = SessionModel(
            session_id=session_id,
            apk_path=apk_path,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.sessions[session_id] = SessionRuntime(model=model)
        return model

    def get_session(self, session_id: str) -> SessionModel | None:
        """Return a session model if it exists."""
        runtime = self.sessions.get(session_id)
        if runtime is None:
            return None
        runtime.model.events = list(runtime.events)
        return runtime.model

    def require_runtime(self, session_id: str) -> SessionRuntime:
        """Return a session runtime or raise KeyError."""
        return self.sessions[session_id]

    def set_static_report(self, session_id: str, report: dict[str, Any]) -> None:
        """Attach a static analysis report to a session."""
        self.require_runtime(session_id).model.static_analysis = report

    def update_session_stats(self, session_id: str, message: dict[str, Any]) -> None:
        """Update session events, stats, risk and alerts from one analyzer message."""
        runtime = self.require_runtime(session_id)
        if "static_analysis" in message and isinstance(message["static_analysis"], dict):
            runtime.model.static_analysis = message["static_analysis"]

        if "event" in message and isinstance(message["event"], dict):
            event = AnalysisEvent.model_validate(message["event"])
            runtime.events.appendleft(event)
            if event.alert:
                runtime.model.alerts.insert(
                    0,
                    Alert(
                        severity=event.severity,
                        message=event.alert,
                        event_type=str(event.type),
                        timestamp=event.timestamp,
                    ),
                )

        if "stats" in message and isinstance(message["stats"], dict):
            runtime.model.stats = EventStats.model_validate(message["stats"])
        if "risk" in message and isinstance(message["risk"], dict):
            runtime.model.risk = RiskReport.model_validate(message["risk"])
            runtime.model.alerts = runtime.model.risk.alerts or runtime.model.alerts

    def start_analyzer(self, session_id: str, adb_serial: str | None = None) -> None:
        """Launch analyzer/main.py as a subprocess for a session."""
        runtime = self.require_runtime(session_id)
        if runtime.process and runtime.process.poll() is None:
            return

        analyzer_main = PROJECT_ROOT / "analyzer" / "main.py"
        log_path = UPLOAD_DIR / f"{session_id}.analyzer.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        backend_ws = os.environ.get("BACKEND_WS_URL", "ws://localhost:8000")
        frida_server = os.environ.get("FRIDA_SERVER_PATH")
        cmd = [
            sys.executable,
            str(analyzer_main),
            runtime.model.apk_path,
            "--session",
            session_id,
            "--ws",
            backend_ws,
        ]
        if adb_serial:
            cmd.extend(["--serial", adb_serial])
        if frida_server:
            cmd.extend(["--frida-server", frida_server])

        log_file = log_path.open("a", encoding="utf-8")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT)
        runtime.process = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=log_file,
            stderr=log_file,
            text=True,
        )
        runtime.model.status = "analyzing"

    def stop_analyzer(self, session_id: str) -> SessionModel:
        """Stop a running analyzer subprocess and return the final session report."""
        runtime = self.require_runtime(session_id)
        if runtime.process and runtime.process.poll() is None:
            if os.name == "nt":
                runtime.process.terminate()
            else:
                os.kill(runtime.process.pid, signal.SIGTERM)
            try:
                runtime.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                runtime.process.kill()
        runtime.model.status = "stopped"
        runtime.model.events = list(runtime.events)
        return runtime.model


session_manager = SessionManager()
