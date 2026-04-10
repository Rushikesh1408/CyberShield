from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from backend.database import Database


@dataclass(frozen=True)
class AttackFingerprint:
    process_name: str
    file_extension: str
    modification_rate: float
    access_rate: float
    cpu_spike: float
    signature_hash: str


class FingerprintManager:
    def __init__(self, database: Database) -> None:
        self.database = database

    @staticmethod
    def _normalize_process_name(process_name: str | None) -> str:
        return (process_name or "unknown").strip().lower()

    @staticmethod
    def _normalize_extension(extension: str | None) -> str:
        extension = (extension or "").strip().lower()
        if not extension:
            return "unknown"
        return extension if extension.startswith(".") else f".{extension}"

    @staticmethod
    def _signature_hash(payload: dict[str, Any]) -> str:
        signature = "|".join(
            [
                str(payload["process_name"]),
                str(payload["file_extension"]),
                f"{payload['modification_rate']:.2f}",
                f"{payload['access_rate']:.2f}",
                f"{payload['cpu_spike']:.2f}",
            ]
        )
        return hashlib.sha256(signature.encode("utf-8")).hexdigest()

    def create(
        self,
        *,
        process_name: str | None,
        file_extension: str | None,
        modification_rate: float,
        access_rate: float,
        cpu_spike: float,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "process_name": self._normalize_process_name(process_name),
            "file_extension": self._normalize_extension(file_extension),
            "modification_rate": round(float(modification_rate), 2),
            "access_rate": round(float(access_rate), 2),
            "cpu_spike": round(float(cpu_spike), 2),
        }
        payload["signature_hash"] = self._signature_hash(payload)
        return payload

    def store(self, fingerprint: dict[str, Any]) -> None:
        self.database.upsert_fingerprint(fingerprint)

    def compare(self, fingerprint: dict[str, Any]) -> dict[str, Any] | None:
        fingerprints = self.database.fetch_fingerprints()
        if not fingerprints:
            return None

        best_match: dict[str, Any] | None = None
        best_score = 0.0
        for stored in fingerprints:
            score = self._score_match(fingerprint, stored)
            if score > best_score:
                best_score = score
                best_match = stored

        if best_match is None or best_score < 0.65:
            return None

        result = dict(best_match)
        result["similarity"] = round(best_score * 100, 1)
        return result

    @staticmethod
    def _score_match(incoming: dict[str, Any], stored: dict[str, Any]) -> float:
        score = 0.0
        weight = 0.0

        weight += 0.35
        if incoming["process_name"] == stored["process_name"]:
            score += 0.35
        elif incoming["process_name"] in stored["process_name"] or stored["process_name"] in incoming["process_name"]:
            score += 0.2

        weight += 0.2
        if incoming["file_extension"] == stored["file_extension"]:
            score += 0.2

        weight += 0.2
        if abs(float(incoming["modification_rate"]) - float(stored["modification_rate"])) <= 4:
            score += 0.2
        elif abs(float(incoming["modification_rate"]) - float(stored["modification_rate"])) <= 10:
            score += 0.1

        weight += 0.15
        if abs(float(incoming["access_rate"]) - float(stored["access_rate"])) <= 6:
            score += 0.15
        elif abs(float(incoming["access_rate"]) - float(stored["access_rate"])) <= 12:
            score += 0.08

        weight += 0.1
        if float(incoming["cpu_spike"]) >= 70 and float(stored["cpu_spike"]) >= 70:
            score += 0.1
        elif abs(float(incoming["cpu_spike"]) - float(stored["cpu_spike"])) <= 20:
            score += 0.05

        return score / weight if weight else 0.0
