"""Pydantic models for analysis sessions and API responses."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from backend.models.event import Alert, AnalysisEvent, EventStats, RiskReport


class SessionModel(BaseModel):
    """Serializable session state."""

    session_id: str
    apk_path: str
    created_at: str
    status: Literal["created", "analyzing", "stopped", "failed"] = "created"
    static_analysis: dict[str, Any] = Field(default_factory=dict)
    stats: EventStats = Field(default_factory=EventStats)
    risk: RiskReport = Field(default_factory=RiskReport)
    events: list[AnalysisEvent] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)


class UploadResponse(BaseModel):
    """Response returned after an APK upload and static analysis."""

    session_id: str
    static_analysis: dict[str, Any]


class StartAnalysisRequest(BaseModel):
    """Body for POST /api/analysis/start."""

    session_id: str
    adb_serial: str | None = None


class StopAnalysisRequest(BaseModel):
    """Body for POST /api/analysis/stop."""

    session_id: str


class StatusResponse(BaseModel):
    """Simple status response."""

    status: str
    session_id: str


class StopAnalysisResponse(BaseModel):
    """Response returned after stopping an analysis."""

    status: str
    final_report: SessionModel
