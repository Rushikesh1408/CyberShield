from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Any, Mapping


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
