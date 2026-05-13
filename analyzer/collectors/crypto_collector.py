"""Cryptography event helpers."""

from __future__ import annotations

from typing import Any

WEAK_ALGORITHMS = {"MD5", "SHA1", "DES", "RC4"}


class CryptoCollector:
    """Classifies crypto operations observed through Frida."""

    @staticmethod
    def is_weak(event_data: dict[str, Any]) -> bool:
        """Return true when a weak algorithm appears in the event."""
        algorithm = str(event_data.get("algorithm") or "").upper()
        return any(weak in algorithm for weak in WEAK_ALGORITHMS)

    @staticmethod
    def summarize(event_data: dict[str, Any]) -> str:
        """Return a compact crypto operation summary."""
        operation = str(event_data.get("operation") or "crypto")
        algorithm = str(event_data.get("algorithm") or "unknown")
        return f"{operation} {algorithm[:80]}"
