from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


VALID_STATES = {"SAFE", "SUSPICIOUS", "ATTACK", "MITIGATION", "RECOVERY"}


class TimelineEngine:
    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def record(self, *, state: str, title: str, details: str, severity: str) -> dict[str, Any]:
        normalized_state = state.strip().upper() if state else "SAFE"
        if normalized_state not in VALID_STATES:
            normalized_state = "SUSPICIOUS"

        entry = {
            "state": normalized_state,
            "title": str(title or normalized_state),
            "details": str(details or ""),
            "severity": str(severity or "info"),
            "timestamp": self._now(),
        }

        if self._entries and self._entries[-1]["state"] == entry["state"]:
            self._entries[-1] = entry
        else:
            self._entries.append(entry)

        self._entries = self._entries[-300:]
        return entry

    def snapshot(self) -> list[dict[str, Any]]:
        return [dict(entry) for entry in self._entries]
