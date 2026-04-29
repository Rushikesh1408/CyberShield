from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any, Mapping
from difflib import SequenceMatcher
import time


def _hash_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate_dna(file_path: str | Path) -> dict[str, Any]:
    """Generate digital DNA using SHA256, file size, and last modified timestamp."""
    path = Path(file_path).resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    stats = path.stat()
    return {
        "hash": _hash_file(path),
        "size": int(stats.st_size),
        "modified": float(stats.st_mtime),
    }


def compare_dna(old: Mapping[str, Any], new: Mapping[str, Any]) -> str:
    """Compare two DNA snapshots and return MATCH or MISMATCH."""
    fields = ("hash", "size", "modified")
    for field in fields:
        if old.get(field) != new.get(field):
            return "MISMATCH"
    return "MATCH"


def generate_dna_signature(event_data):
    """
    Generate a structured DNA signature from event data.
    """
    sig = {
        "id": hashlib.sha256(
            json.dumps(event_data, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, default=str).encode('utf-8')
        ).hexdigest(),
        "actions": event_data.get("actions", []),
        "extensions": event_data.get("extensions", []),
        "speed": event_data.get("speed", "unknown"),
        "sequence": event_data.get("sequence", []),
        "impact_score": event_data.get("impact_score", 0),
        "timestamp": time.time(),
        "source_node": event_data.get("source_node", "local")
    }
    return sig


def dna_similarity(sig1, sig2):
    """
    Compute similarity score (0-100) between two DNA signatures.
    """
    score = 0
    actions1 = set(sig1.get("actions", []))
    actions2 = set(sig2.get("actions", []))
    if actions1 or actions2:
        score += 30 * len(actions1 & actions2) / max(len(actions1 | actions2), 1)
    ext1 = set(sig1.get("extensions", []))
    ext2 = set(sig2.get("extensions", []))
    if ext1 or ext2:
        score += 20 * len(ext1 & ext2) / max(len(ext1 | ext2), 1)
    seq1 = sig1.get("sequence", [])
    seq2 = sig2.get("sequence", [])
    if seq1 and seq2:
        seq_score = SequenceMatcher(None, seq1, seq2).ratio()
        score += 30 * seq_score
    if sig1.get("speed") == sig2.get("speed"):
        score += 10
    s1_impact = sig1.get("impact_score", 0)
    s2_impact = sig2.get("impact_score", 0)
    s1_impact = 0 if s1_impact is None else s1_impact
    s2_impact = 0 if s2_impact is None else s2_impact
    try:
        if abs(float(s1_impact) - float(s2_impact)) <= 10:
            score += 10
    except (TypeError, ValueError):
        pass
    return round(score)


class DigitalDNAStore:
    """Thread-safe DNA cache that hashes files only when metadata changed."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: dict[str, dict[str, Any]] = {}

    def generate_if_modified(self, file_path: str | Path) -> tuple[dict[str, Any], bool]:
        path = Path(file_path).resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        stats = path.stat()
        key = str(path)
        with self._lock:
            cached = self._cache.get(key)
            if (
                cached is not None
                and int(cached.get("size", -1)) == int(stats.st_size)
                and float(cached.get("modified", -1.0)) == float(stats.st_mtime)
            ):
                return cached.copy(), False

        dna = {
            "hash": _hash_file(path),
            "size": int(stats.st_size),
            "modified": float(stats.st_mtime),
        }
        with self._lock:
            self._cache[key] = dna
        return dna.copy(), True
