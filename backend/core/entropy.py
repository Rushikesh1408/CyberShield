from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any


def calculate_entropy(
    file_path: str | Path,
    *,
    chunk_size: int = 64 * 1024,
    max_bytes: int = 256 * 1024,
) -> float:
    path = Path(file_path).resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    histogram = [0] * 256
    total_bytes = 0
    with path.open("rb") as handle:
        while True:
            if total_bytes >= max_bytes:
                break
            remaining = max_bytes - total_bytes
            read_size = min(chunk_size, remaining)
            if read_size <= 0:
                break

            chunk = handle.read(read_size)
            if not chunk:
                break
            total_bytes += len(chunk)
            for value in chunk:
                histogram[value] += 1

    if total_bytes <= 0:
        return 0.0

    entropy = 0.0
    for count in histogram:
        if count <= 0:
            continue
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def get_entropy_score(file_path: str | Path) -> dict[str, Any]:
    score = calculate_entropy(file_path)
    return {
        "score": float(score),
        "likely_encrypted": float(score) > 7.5,
    }


def calculate_file_dna(file_path: str | Path, *, chunk_size: int = 1024 * 1024) -> dict[str, Any]:
    path = Path(file_path).resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            size += len(chunk)
            digest.update(chunk)

    stats = path.stat()
    return {
        "path": str(path),
        "hash": digest.hexdigest(),
        "size": int(size),
        "modified": float(stats.st_mtime),
    }
