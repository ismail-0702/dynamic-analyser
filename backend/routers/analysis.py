"""Analysis lifecycle routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.models.session import StartAnalysisRequest, StatusResponse, StopAnalysisRequest, StopAnalysisResponse, SessionModel
from backend.services.event_broadcaster import broadcaster
from backend.services.session_manager import session_manager

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


@router.post("/start", response_model=StatusResponse)
async def start_analysis(body: StartAnalysisRequest) -> StatusResponse:
    """Start the dynamic analyzer subprocess for a session."""
    if session_manager.get_session(body.session_id) is None:
        raise HTTPException(
            status_code=404,
            detail="Session introuvable — uploadez à nouveau l'APK (le backend a peut-être redémarré)",
        )
    try:
        session_manager.start_analyzer(body.session_id, body.adb_serial)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not start analyzer: {exc}") from exc
    await broadcaster.broadcast(
        body.session_id,
        {"kind": "status", "payload": {"status": "analyzing"}},
    )
    return StatusResponse(status="started", session_id=body.session_id)


@router.post("/stop", response_model=StopAnalysisResponse)
async def stop_analysis(body: StopAnalysisRequest) -> StopAnalysisResponse:
    """Stop the dynamic analyzer subprocess and return the final report."""
    if session_manager.get_session(body.session_id) is None:
        raise HTTPException(
            status_code=404,
            detail="Session introuvable — uploadez à nouveau l'APK (le backend a peut-être redémarré)",
        )
    report = session_manager.stop_analyzer(body.session_id)
    await broadcaster.broadcast(
        body.session_id,
        {"kind": "status", "payload": {"status": "stopped"}},
    )
    return StopAnalysisResponse(status="stopped", final_report=report)


@router.get("/{session_id}/report", response_model=SessionModel)
async def get_report(session_id: str) -> SessionModel:
    """Return the current full static and dynamic report."""
    session = session_manager.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return session
