"""Realtime risk scoring for static and dynamic APK analysis signals."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

JsonDict = dict[str, Any]
RuleCondition = Callable[[JsonDict], bool]
DynamicRule = tuple[str, RuleCondition, int, str, str, str]
StaticRule = tuple[str, bool, int, str]

RISK_WEIGHTS: dict[str, float] = {
    "network": 0.25,
    "permissions": 0.25,
    "crypto": 0.20,
    "behavior": 0.20,
    "static": 0.10,
}

DYNAMIC_RULES: list[DynamicRule] = [
    ("network", lambda e: "geo." in e.get("url", ""), 30, "network", "high", "Geolocalisation IP"),
    ("network", lambda e: "tracking" in e.get("url", ""), 25, "network", "high", "Tracker tiers"),
    ("network", lambda e: e.get("url", "").startswith("http://"), 20, "network", "medium", "Trafic HTTP non chiffre"),
    ("crypto", lambda e: e.get("algorithm", "") in ["MD5", "DES", "RC4"], 35, "crypto", "high", "Algorithme obsolete"),
    ("crypto", lambda e: int(e.get("key_length", 256) or 256) < 128, 25, "crypto", "high", "Cle trop courte"),
    ("permission", lambda e: "RECORD_AUDIO" in str(e), 30, "permissions", "high", "Acces microphone"),
    ("permission", lambda e: "ACCESS_FINE_LOCATION" in str(e), 25, "permissions", "high", "GPS precis"),
    ("permission", lambda e: "READ_SMS" in str(e), 35, "permissions", "critical", "Lecture SMS"),
    ("sensor", lambda e: "AudioRecord" in str(e), 40, "behavior", "critical", "Enregistrement audio"),
    ("anti_analysis", lambda _e: True, 30, "behavior", "high", "Tentative anti-analyse"),
    ("sql", lambda e: "password" in e.get("query", "").lower(), 30, "behavior", "high", "Acces colonne password"),
    ("file", lambda e: ".hidden" in e.get("path", ""), 25, "behavior", "high", "Fichier cache"),
]

STATIC_RULES: list[StaticRule] = [
    ("debuggable", True, 20, "Manifest debuggable=true"),
    ("allow_backup", True, 10, "Backup ADB active"),
    ("uses_cleartext_traffic", True, 15, "Cleartext HTTP autorise"),
]


class RiskScorer:
    """Maintains a weighted risk score from dynamic events and static findings."""

    def __init__(self) -> None:
        self.scores: dict[str, int] = {key: 0 for key in RISK_WEIGHTS}
        self.alerts: list[JsonDict] = []
        self.events_seen: set[str] = set()

    def process_event(self, event: JsonDict) -> list[JsonDict]:
        """Process one dynamic event and return newly generated alerts."""
        event_type = str(event.get("type", "unknown"))
        data = event.get("data", {})
        if not isinstance(data, dict):
            data = {"message": str(data)}

        new_alerts: list[JsonDict] = []
        for index, (rule_type, condition, points, dimension, severity, message) in enumerate(DYNAMIC_RULES):
            if event_type != rule_type:
                continue
            try:
                triggered = condition(data)
            except (TypeError, ValueError, KeyError):
                triggered = False
            if not triggered:
                continue

            rule_key = self._dynamic_key(index, event_type, data)
            if rule_key in self.events_seen:
                continue

            self.events_seen.add(rule_key)
            self.scores[dimension] = min(100, self.scores[dimension] + points)
            alert = self._build_alert(severity, message, event_type, event.get("timestamp"))
            self.alerts.append(alert)
            new_alerts.append(alert)

        return new_alerts

    def process_static(self, static_report: JsonDict) -> list[JsonDict]:
        """Fold static APK analysis findings into the risk model."""
        new_alerts: list[JsonDict] = []
        manifest = static_report.get("manifest", {})
        if not isinstance(manifest, dict):
            manifest = {}

        for key, expected, points, message in STATIC_RULES:
            if manifest.get(key) is expected:
                rule_key = f"static:{key}:{expected}"
                if rule_key in self.events_seen:
                    continue
                self.events_seen.add(rule_key)
                self.scores["static"] = min(100, self.scores["static"] + points)
                alert = self._build_alert("medium", message, "static", None)
                self.alerts.append(alert)
                new_alerts.append(alert)

        permissions = static_report.get("permissions", [])
        if isinstance(permissions, list):
            dangerous_count = sum(1 for item in permissions if isinstance(item, dict) and item.get("severity") in {"high", "critical"})
            if dangerous_count:
                points = min(50, dangerous_count * 8)
                self.scores["permissions"] = min(100, self.scores["permissions"] + points)
                alert = self._build_alert("high", f"{dangerous_count} permissions dangereuses declarees", "permission", None)
                self.alerts.append(alert)
                new_alerts.append(alert)

        secrets = static_report.get("secrets", [])
        if isinstance(secrets, list) and secrets:
            self.scores["static"] = min(100, self.scores["static"] + min(60, len(secrets) * 15))
            alert = self._build_alert("critical", f"{len(secrets)} secrets potentiels hardcodes", "static", None)
            self.alerts.append(alert)
            new_alerts.append(alert)

        return new_alerts

    def get_global_score(self) -> int:
        """Return the weighted global score from 0 to 100."""
        score = sum(self.scores[dimension] * weight for dimension, weight in RISK_WEIGHTS.items())
        return min(100, round(score))

    def get_report(self) -> JsonDict:
        """Return a serializable risk report with score, level, dimensions and alerts."""
        score = self.get_global_score()
        return {
            "global_score": score,
            "level": self._level(score),
            "dimensions": deepcopy(self.scores),
            "alerts": deepcopy(self.alerts),
            "alerts_count": self._alert_counts(),
        }

    @staticmethod
    def _level(score: int) -> str:
        if score < 40:
            return "low"
        if score < 70:
            return "medium"
        if score < 90:
            return "high"
        return "critical"

    @staticmethod
    def _build_alert(severity: str, message: str, event_type: str, timestamp: Any) -> JsonDict:
        return {
            "severity": severity,
            "message": message,
            "event_type": event_type,
            "timestamp": str(timestamp or datetime.now(timezone.utc).isoformat()),
        }

    @staticmethod
    def _dynamic_key(index: int, event_type: str, data: JsonDict) -> str:
        indicator = data.get("url") or data.get("path") or data.get("query") or data.get("algorithm") or data.get("operation") or ""
        return f"dynamic:{index}:{event_type}:{str(indicator)[:80]}"

    def _alert_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for alert in self.alerts:
            severity = str(alert.get("severity", "low"))
            counts[severity] = counts.get(severity, 0) + 1
        return counts
