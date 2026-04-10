from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatScore:
    score: int
    level: str


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def _threat_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def calculate_threat_score(
    *,
    file_activity_count: int,
    cpu_usage: float,
    dna_mismatch_count: int,
    max_file_activity: int = 200,
    max_dna_mismatch: int = 20,
) -> dict[str, int | str]:
    """Compute weighted ransomware threat score in the range 0-100."""
    safe_max_file_activity = max(1, int(max_file_activity))
    safe_max_dna_mismatch = max(1, int(max_dna_mismatch))

    file_activity_score = _clamp01(float(file_activity_count) / float(safe_max_file_activity))
    cpu_score = _clamp01(float(cpu_usage) / 100.0)
    dna_score = _clamp01(float(dna_mismatch_count) / float(safe_max_dna_mismatch))

    weighted_score = (
        0.6 * file_activity_score
        + 0.15 * cpu_score
        + 0.25 * dna_score
    )
    score = int(round(_clamp01(weighted_score) * 100.0))
    level = _threat_level(score)

    return ThreatScore(score=score, level=level).__dict__.copy()
