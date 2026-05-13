"""WebSocket broadcaster for multi-client dashboard sessions."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from fastapi import WebSocket

log = logging.getLogger(__name__)


class EventBroadcaster:

    def __init__(self) -> None:
        self._clients: dict[str, set[WebSocket]] = defaultdict(set)

    async def connect(self, session_id: str, websocket: WebSocket) -> None:
        self._clients[session_id].add(websocket)

    def disconnect(self, session_id: str, websocket: WebSocket) -> None:
        self._clients[session_id].discard(websocket)

    async def broadcast(self, session_id: str, message: dict[str, Any]) -> None:
        stale: list[WebSocket] = []
        for client in self._clients[session_id]:
            try:
                await client.send_json(message)
            except Exception as exc:
                log.debug("Dropping stale WebSocket: %s", exc)
                stale.append(client)
        for client in stale:
            self.disconnect(session_id, client)


broadcaster = EventBroadcaster()