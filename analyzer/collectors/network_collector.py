"""Network event normalization helpers."""

from __future__ import annotations

from typing import Any


class NetworkCollector:
    """Builds compact summaries from Frida network events."""

    @staticmethod
    def summarize(event_data: dict[str, Any]) -> str:
        """Return a safe one-line network summary."""
        method = str(event_data.get("method") or "HTTP")
        url = str(event_data.get("url") or "")
        code = event_data.get("response_code")
        suffix = f" -> {code}" if code is not None else ""
        return f"{method} {url[:120]}{suffix}"
