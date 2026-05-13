"""Shared WebSocket endpoint for analyzer ingestion and dashboard clients."""

from __future__ import annotations

import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.services.event_broadcaster import broadcaster
from backend.services.session_manager import session_manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str) -> None:
    await websocket.accept()
    role = websocket.query_params.get("role", "dashboard")
    if role == "analyzer":
        await _handle_analyzer(websocket, session_id)
        return

    await broadcaster.connect(session_id, websocket)
    session = session_manager.get_session(session_id)
    if session:
        await websocket.send_json({"kind": "snapshot", "payload": session.model_dump(mode="json")})
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        broadcaster.disconnect(session_id, websocket)


async def _handle_analyzer(websocket: WebSocket, session_id: str) -> None:
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if session_manager.get_session(session_id) is not None:
                session_manager.update_session_stats(session_id, message)
            await broadcaster.broadcast(session_id, {"kind": "message", "payload": message})
    except WebSocketDisconnect:
        session = session_manager.get_session(session_id)
        if session and session.status == "analyzing":
            session.status = "failed"
        await broadcaster.broadcast(session_id, {"kind": "status", "payload": {"status": "disconnected"}})
