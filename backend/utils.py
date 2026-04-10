from __future__ import annotations

from pathlib import Path
from typing import Iterable


def existing_directories(candidates: Iterable[str | Path]) -> list[Path]:
    """Return unique existing directory paths while preserving input order."""
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        resolved = Path(candidate).resolve()
        if not resolved.exists() or not resolved.is_dir():
            continue
        key = str(resolved).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(resolved)
    return unique


def normalize_contact_value(value: str) -> str:
    """Normalize user-entered emergency contact to a compact, storable string."""
    return " ".join(value.strip().split())
