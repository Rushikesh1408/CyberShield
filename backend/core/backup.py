from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from ..backup import BackupManager as _BackupManager


class VersionedSnapshotManager:
    """Core wrapper around the existing BackupManager for pipeline integration."""

    def __init__(self, source_roots: Iterable[str | Path], backup_root: str | Path) -> None:
        self._manager = _BackupManager(source_roots=source_roots, backup_root=backup_root)

    def create_snapshot(self, source_path: str | Path, *, force: bool = False) -> dict[str, Any] | None:
        result = self._manager.backup_file(source_path=source_path, force=force)
        if result is None:
            return None
        return {
            "source_path": result.source_path,
            "backup_path": result.backup_path,
            "version": int(result.version),
        }

    def snapshot_folder(self, folder: str | Path | None = None) -> list[dict[str, Any]]:
        results = self._manager.snapshot_folder(folder)
        payload: list[dict[str, Any]] = []
        for result in results:
            payload.append(
                {
                    "source_path": result.source_path,
                    "backup_path": result.backup_path,
                    "version": int(result.version),
                }
            )
        return payload

    def status(self, *, force_refresh: bool = False) -> dict[str, Any]:
        data = self._manager.backup_status(force_refresh=force_refresh)
        return {
            "files_secured": int(data.get("files_secured", 0)),
            "backup_versions": int(data.get("backup_versions", 0)),
            "last_backup_time": data.get("last_backup_time"),
            "recent_files": list(data.get("recent_files", [])),
            "backup_root": str(data.get("backup_root", "")),
        }

    def list_versions(self, source_path: str | Path) -> list[dict[str, Any]]:
        versions = self._manager.list_versions(source_path)
        payload: list[dict[str, Any]] = []
        for index, item in enumerate(versions, start=1):
            payload.append(
                {
                    "version": index,
                    "path": str(item.get("path", "")),
                    "size": int(item.get("size", 0)),
                    "modified": float(item.get("modified", 0.0)),
                }
            )
        return payload

    @property
    def manager(self) -> _BackupManager:
        return self._manager
