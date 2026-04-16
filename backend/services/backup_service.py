from __future__ import annotations

import time
from pathlib import Path
from typing import Iterable

from backend.backup import BackupManager, BackupResult


class BackupService:
    def __init__(
        self,
        *,
        monitored_paths: Iterable[str | Path],
        backup_root: str | Path,
        backup_manager: BackupManager | None = None,
    ) -> None:
        self.monitored_paths = [Path(path).resolve() for path in monitored_paths]
        self.backup_root = Path(backup_root).resolve()
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self.backup_manager = backup_manager or BackupManager(self.monitored_paths, self.backup_root)

    def discover_recent_files(self, *, lookback_seconds: float = 5.0) -> list[Path]:
        cutoff = time.time() - max(0.5, float(lookback_seconds))
        recent_files: list[Path] = []
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

                if modified < cutoff:
                    continue

                key = str(file_path.resolve()).lower()
                if key in seen:
                    continue

                seen.add(key)
                recent_files.append(file_path)

        recent_files.sort(key=lambda path: path.stat().st_mtime if path.exists() else 0.0, reverse=True)
        return recent_files

    @staticmethod
    def _result_to_payload(result: BackupResult) -> dict[str, object]:
        return {
            "source_path": result.source_path,
            "backup_path": result.backup_path,
            "version": int(result.version),
        }

    def backup_active_files(self, *, lookback_seconds: float = 5.0) -> dict[str, object]:
        recent_files = self.discover_recent_files(lookback_seconds=lookback_seconds)
        results: list[dict[str, object]] = []
        protected_sources: set[str] = set()

        for file_path in recent_files:
            try:
                result = self.backup_manager.backup_file(file_path, force=True)
            except (OSError, ValueError):
                continue

            if result is None:
                continue

            payload = self._result_to_payload(result)
            results.append(payload)
            protected_sources.add(str(payload["source_path"]).lower())

        return {
            "files_protected": len(protected_sources),
            "backup_versions": len(results),
            "recent_files": [str(path) for path in recent_files],
            "results": results,
            "backup_root": str(self.backup_root),
        }

    def detect_backup_folder_access(self, paths: Iterable[str | Path]) -> list[str]:
        access_hits: list[str] = []
        backup_root = self.backup_root.resolve()
        for value in paths:
            try:
                candidate = Path(value).resolve()
            except OSError:
                continue

            try:
                candidate.relative_to(backup_root)
            except ValueError:
                continue

            access_hits.append(str(candidate))

        return access_hits

    def build_backup_protection_alerts(self, paths: Iterable[str | Path]) -> list[dict[str, object]]:
        hits = self.detect_backup_folder_access(paths)
        return [
            {
                "event": "backup_folder_access",
                "severity": "critical",
                "message": "Backup protection layer detected direct access to backup storage.",
                "path": path,
            }
            for path in hits
        ]

    def protected_inventory(self) -> dict[str, int]:
        backup_files = [path for path in self.backup_root.rglob("*") if path.is_file()]
        unique_sources: set[str] = set()
        for backup_file in backup_files:
            relative = backup_file.relative_to(self.backup_root)
            if len(relative.parts) < 2:
                continue
            source_relative = Path(*relative.parts[1:])
            stem = source_relative.stem
            original_name = stem.rsplit("_v", 1)[0] if "_v" in stem else stem
            source_path = source_relative.with_name(f"{original_name}{source_relative.suffix}")
            unique_sources.add(str(source_path.resolve()).lower())

        return {
            "files_secured": len(unique_sources),
            "backup_versions": len(backup_files),
        }
