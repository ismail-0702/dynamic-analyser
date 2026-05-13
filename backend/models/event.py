"""Pydantic models for analyzer events and risk reports."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

EventType = Literal[
    "network",
    "file",
    "crypto",
    "sql",
    "permission",
    "ipc",
    "sensor",
    "clipboard",
    "location",
    "anti_analysis",
    "hook_error",
    "system",
]
Severity = Literal["info", "low", "medium", "high", "critical"]


class AnalysisEvent(BaseModel):
    """One event emitted by Frida and normalized by analyzer.py."""

    type: EventType | str
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: str
    ts_unix: float
    severity: Severity = "info"
    alert: str | None = None


class EventStats(BaseModel):
    """Realtime event counters for one session."""

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


class Alert(BaseModel):
    """Risk alert generated from static or dynamic rules."""

    severity: Severity
    message: str
    event_type: str
    timestamp: str


class RiskReport(BaseModel):
    """Weighted risk score and per-dimension breakdown."""

    global_score: int = 0
    level: Literal["low", "medium", "high", "critical"] = "low"
    dimensions: dict[str, int] = Field(
        default_factory=lambda: {"network": 0, "permissions": 0, "crypto": 0, "behavior": 0, "static": 0}
    )
    alerts: list[Alert] = Field(default_factory=list)
    alerts_count: dict[str, int] = Field(default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})


class WSMessage(BaseModel):
    """Message sent from analyzer.py to backend and then to dashboard clients."""

    event: AnalysisEvent
    stats: EventStats
    risk: RiskReport
