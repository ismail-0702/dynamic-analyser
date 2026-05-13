"""Permission event helpers."""

from __future__ import annotations

from typing import Any

HIGH_RISK_PERMISSIONS = {"ACCESS_FINE_LOCATION", "RECORD_AUDIO", "READ_SMS", "CAMERA"}


class PermissionCollector:
    """Normalizes Android permission names and computes severity hints."""

    @staticmethod
    def normalize(permission: str) -> str:
        """Remove the android.permission prefix when present."""
        return permission.replace("android.permission.", "")

    @classmethod
    def severity(cls, event_data: dict[str, Any]) -> str:
        """Return a severity hint for runtime permission activity."""
        permissions = event_data.get("permissions") or []
        if isinstance(permissions, str):
            permissions = [permissions]
        normalized = {cls.normalize(str(permission)) for permission in permissions}
        return "high" if normalized & HIGH_RISK_PERMISSIONS else "low"
