"""Filesystem event helpers."""

from __future__ import annotations

from typing import Any

NOISY_PREFIXES = ("/proc", "/sys", "/dev")


class FileCollector:
    """Filters and summarizes filesystem events."""

    @staticmethod
    def should_keep(event_data: dict[str, Any]) -> bool:
        """Return false for noisy kernel/device paths."""
        path = str(event_data.get("path") or "")
        return not path.startswith(NOISY_PREFIXES)

    @staticmethod
    def summarize(event_data: dict[str, Any]) -> str:
        """Return a compact file operation summary."""
        operation = str(event_data.get("operation") or "FILE")
        path = str(event_data.get("path") or event_data.get("key") or "")
        return f"{operation} {path[:140]}"
