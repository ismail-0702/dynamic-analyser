"""Async WebSocket client used by the analyzer to stream events."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import websockets

log = logging.getLogger(__name__)


class AnalyzerWebSocketClient:
    """Maintains a reconnecting WebSocket connection to the FastAPI backend."""

    def __init__(self, base_uri: str, session_id: str) -> None:
        """Create a client for a backend base URI such as ws://localhost:8000."""
        self.base_uri = base_uri.rstrip("/")
        self.session_id = session_id
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._stop = asyncio.Event()

    async def send(self, message: dict[str, Any]) -> None:
        """Queue one message for delivery."""
        await self.queue.put(message)

    async def stop(self) -> None:
        """Stop the send loop."""
        self._stop.set()

    async def run(self) -> None:
        """Connect, send queued messages, and reconnect every three seconds on failure."""
        while not self._stop.is_set():
            try:
                async with websockets.connect(f"{self.base_uri}/ws/{self.session_id}?role=analyzer", ping_interval=20) as websocket:
                    log.info("Connected analyzer WebSocket for session %s", self.session_id)
                    while not self._stop.is_set():
                        message = await self.queue.get()
                        await websocket.send(json.dumps(message))
            except (OSError, websockets.ConnectionClosed) as exc:
                log.warning("WebSocket unavailable: %s; reconnecting in 3s", exc)
                await asyncio.sleep(3)
