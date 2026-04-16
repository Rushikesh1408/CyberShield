from __future__ import annotations

import time
from pathlib import Path
from typing import Iterable

from backend.core.restore import RestoreManager


class RecoveryService:
    def __init__(self, *, monitored_paths: Iterable[str | Path], backup_root: str | Path) -> None:
        self.monitored_paths = [Path(path).resolve() for path in monitored_paths]
        self.backup_root = Path(backup_root).resolve()
        self.restore_manager = RestoreManager(self.monitored_paths, self.backup_root)

    def discover_affected_files(self, *, lookback_seconds: float = 5.0) -> list[str]:
        cutoff = time.time() - max(0.5, float(lookback_seconds))
        candidates: list[str] = []
        seen: set[str] = set()

        for root in self.monitored_paths:
            if not root.exists() or not root.is_dir():
                continue

            for file_path in root.rglob("*"):
                if not file_path.is_file():
                    continue

                try:
                    modified = file_path.stat().st_mtime
                except OSError:
                    continue

                if modified < cutoff and file_path.suffix.lower() != ".enc":
                    continue

                candidate = file_path
                if file_path.suffix.lower() == ".enc" and file_path.stem:
                    candidate = file_path.with_name(file_path.stem)

                resolved = str(candidate.resolve())
                key = resolved.lower()
                if key in seen:
                    continue

                seen.add(key)
                candidates.append(resolved)

        return candidates

    def restore_affected_files(
        self,
        *,
        file_paths: Iterable[str | Path] | None = None,
        before_timestamp: float | None = None,
        lookback_seconds: float = 5.0,
    ) -> dict[str, object]:
        raw_candidates = list(file_paths) if file_paths is not None else self.discover_affected_files(
            lookback_seconds=lookback_seconds,
        )
        normalized_candidates: list[str] = []
        seen: set[str] = set()

        for value in raw_candidates:
            candidate = Path(value)
            path_to_restore = candidate
            if candidate.suffix.lower() == ".enc" and candidate.stem:
                path_to_restore = candidate.with_name(candidate.stem)

            try:
                resolved = str(path_to_restore.resolve())
            except OSError:
                continue

            key = resolved.lower()
            if key in seen:
                continue

            seen.add(key)
            normalized_candidates.append(resolved)

        restored = self.restore_manager.restore_many(
            normalized_candidates,
            before_timestamp=before_timestamp,
        )

        return {
            "files_restored": len(restored),
            "restored_files": restored,
            "candidates": normalized_candidates,
            "backup_root": str(self.backup_root),
        }
