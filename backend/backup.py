from __future__ import annotations

import hashlib
import re
import shutil
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


_VERSION_SUFFIX_PATTERN = re.compile(r"_v(\d+)$")
DEFAULT_MAX_BACKUPS_PER_FILE = 5


@dataclass(frozen=True)
class BackupResult:
    source_path: str
    backup_path: str
    version: int


class BackupManager:
    def __init__(
        self,
        source_roots: Iterable[str | Path],
        backup_root: str | Path,
        max_backups_per_file: int = DEFAULT_MAX_BACKUPS_PER_FILE,
    ) -> None:
        normalized_roots = [Path(path).resolve() for path in source_roots]
        unique_roots: list[Path] = []
        seen: set[str] = set()
        for root in normalized_roots:
            key = str(root).lower()
            if key not in seen:
                unique_roots.append(root)
                seen.add(key)
        if not unique_roots:
            raise ValueError("source_roots cannot be empty")

        self.source_roots = unique_roots
        self.backup_root = Path(backup_root).resolve()
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self.max_backups_per_file = max(1, int(max_backups_per_file))
        self._lock = threading.Lock()
        self._hash_cache: dict[str, str] = {}
        self._root_labels = self._build_root_labels(self.source_roots)
        self._label_to_root = {label: Path(root) for root, label in self._root_labels.items()}
        self._known_sources: set[str] = set()
        self._status_cache: dict[str, object] | None = {
            "files_secured": 0,
            "backup_versions": 0,
            "last_backup_time": None,
            "recent_files": [],
            "backup_root": str(self.backup_root),
        }
        self._status_cache_at = 0.0
        self._status_cache_ttl_seconds = 15.0

    @staticmethod
    def _sanitize_root_label(path: Path) -> str:
        raw = path.name or "root"
        sanitized = "".join(character if character.isalnum() else "_" for character in raw).strip("_")
        return (sanitized or "root").lower()

    def _build_root_labels(self, roots: list[Path]) -> dict[str, str]:
        labels: dict[str, str] = {}
        used: set[str] = set()
        for root in roots:
            candidate = self._sanitize_root_label(root)
            label = candidate
            suffix = 1
            while label in used:
                label = f"{candidate}_{suffix}"
                suffix += 1
            labels[str(root)] = label
            used.add(label)
        return labels

    def _resolve_scope(self, path: str | Path) -> tuple[str, Path] | None:
        resolved = Path(path).resolve()
        for root in self.source_roots:
            try:
                relative = resolved.relative_to(root)
                label = self._root_labels[str(root)]
                return label, relative
            except ValueError:
                continue
        return None

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _versioned_name(relative_path: Path, version: int) -> Path:
        stem = relative_path.stem
        suffix = relative_path.suffix
        return relative_path.with_name(f"{stem}_v{version}{suffix}")

    def _existing_versions(self, root_label: str, relative_path: Path) -> list[Path]:
        backup_dir = self.backup_root / root_label / relative_path.parent
        if not backup_dir.exists():
            return []
        pattern = f"{relative_path.stem}_v*{relative_path.suffix}"
        return sorted(backup_dir.glob(pattern))

    @staticmethod
    def _remove_version_suffix(file_name_stem: str) -> str:
        return re.sub(r"_v\d+$", "", file_name_stem)

    @staticmethod
    def _extract_version_number(path: Path) -> int:
        match = _VERSION_SUFFIX_PATTERN.search(path.stem)
        if match is None:
            return 0

        try:
            return int(match.group(1))
        except (TypeError, ValueError):
            return 0

    def _next_version_number(self, versions: list[Path]) -> int:
        if not versions:
            return 1
        return max(self._extract_version_number(path) for path in versions) + 1

    def _prune_versions_to_limit(self, versions: list[Path]) -> int:
        overflow = len(versions) - self.max_backups_per_file + 1
        if overflow <= 0:
            return 0

        removed = 0
        by_oldest = sorted(versions, key=lambda path: path.stat().st_mtime)
        for stale_version in by_oldest[:overflow]:
            try:
                stale_version.unlink()
                removed += 1
            except OSError:
                continue
        return removed

    def _source_path_from_backup(self, backup_path: Path) -> Path | None:
        try:
            relative = backup_path.relative_to(self.backup_root)
        except ValueError:
            return None

        if len(relative.parts) < 2:
            return None

        root_label = relative.parts[0]
        source_root = self._label_to_root.get(root_label)
        if source_root is None:
            return None

        relative_with_version = Path(*relative.parts[1:])
        restored_name = f"{self._remove_version_suffix(relative_with_version.stem)}{relative_with_version.suffix}"
        source_relative = relative_with_version.with_name(restored_name)
        return (source_root / source_relative).resolve()

    def _invalidate_status_cache(self) -> None:
        self._status_cache = None
        self._status_cache_at = 0.0

    @staticmethod
    def _as_int(value: object, default: int = 0) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return default
        return default

    @staticmethod
    def _as_str_list(value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str)]

    def _record_backup_write(
        self,
        source_path: Path,
        backup_modified: float | None = None,
        *,
        version_delta: int = 1,
    ) -> None:
        if self._status_cache is None:
            self._status_cache = {
                "files_secured": 0,
                "backup_versions": 0,
                "last_backup_time": None,
                "recent_files": [],
                "backup_root": str(self.backup_root),
            }

        source_key = str(source_path.resolve())
        if source_key not in self._known_sources:
            self._known_sources.add(source_key)
            self._status_cache["files_secured"] = self._as_int(self._status_cache.get("files_secured", 0)) + 1

        # Use branch's safer version_delta approach
        current_versions = int(self._status_cache.get("backup_versions", 0))
        self._status_cache["backup_versions"] = max(0, current_versions + int(version_delta))

        timestamp = datetime.fromtimestamp(
            backup_modified if backup_modified is not None else time.time(),
            timezone.utc,
        ).isoformat()
        self._status_cache["last_backup_time"] = timestamp

        recent_files = self._as_str_list(self._status_cache.get("recent_files", []))
        if source_key in recent_files:
            recent_files.remove(source_key)
        recent_files.insert(0, source_key)
        self._status_cache["recent_files"] = recent_files[:25]
        self._status_cache_at = time.time()

    @staticmethod
    def _clone_status_payload(payload: dict[str, object]) -> dict[str, object]:
        clone = dict(payload)
        clone["recent_files"] = BackupManager._as_str_list(payload.get("recent_files", []))
        return clone

    def backup_status(self, *, force_refresh: bool = False) -> dict[str, object]:
        with self._lock:
            if (
                not force_refresh
                and self._status_cache is not None
            ):
                return self._clone_status_payload(self._status_cache)

        backup_files = [path for path in self.backup_root.rglob("*") if path.is_file()]

        unique_sources: dict[str, float] = {}
        managed_backup_versions = 0
        latest_timestamp = 0.0
        for backup_path in backup_files:
            source_path = self._source_path_from_backup(backup_path)
            if source_path is None:
                continue

            managed_backup_versions += 1
            modified = backup_path.stat().st_mtime
            if modified > latest_timestamp:
                latest_timestamp = modified

            source_key = str(source_path)
            current_seen = unique_sources.get(source_key, 0.0)
            if modified > current_seen:
                unique_sources[source_key] = modified

        recent_files = [
            source_path
            for source_path, _ in sorted(unique_sources.items(), key=lambda item: item[1], reverse=True)[:25]
        ]
        known_sources = set(unique_sources.keys())

        payload = {
            "files_secured": len(unique_sources),
            "backup_versions": managed_backup_versions,
            "last_backup_time": (
                datetime.fromtimestamp(latest_timestamp, timezone.utc).isoformat() if latest_timestamp > 0 else None
            ),
            "recent_files": recent_files,
            "backup_root": str(self.backup_root),
        }
        with self._lock:
            self._known_sources = known_sources
            self._status_cache = payload
            self._status_cache_at = time.time()
        return self._clone_status_payload(payload)

    def backup_file(self, source_path: str | Path, *, force: bool = False) -> BackupResult | None:
        path = Path(source_path)
        if not path.exists() or path.is_dir():
            return None

        scope = self._resolve_scope(path)
        if scope is None:
            return None

        root_label, relative_path = scope

        current_hash = self._hash_file(path)
        cache_key = f"{root_label}:{relative_path.as_posix()}"

        with self._lock:
            if not force and self._hash_cache.get(cache_key) == current_hash:
                return None

            versions = self._existing_versions(root_label, relative_path)
            if len(versions) >= self.max_backups_per_file:
                return None

            version_number = self._next_version_number(versions)
            destination = (
                self.backup_root
                / root_label
                / self._versioned_name(
                    relative_path,
                    version_number,
                )
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
            self._hash_cache[cache_key] = current_hash
            self._record_backup_write(path, destination.stat().st_mtime)
            return BackupResult(str(path), str(destination), version_number)

    def snapshot_folder(self, folder: str | Path | None = None) -> list[BackupResult]:
        roots = [Path(folder).resolve()] if folder else self.source_roots
        results: list[BackupResult] = []
        for root in roots:
            if not root.exists() or not root.is_dir():
                continue
            for file_path in root.rglob("*"):
                if file_path.is_file():
                    result = self.backup_file(file_path, force=False)
                    if result is not None:
                        results.append(result)
        return results

    def restore_file(self, source_path: str | Path, *, before_timestamp: float | None = None) -> Path | None:
        path = Path(source_path)
        scope = self._resolve_scope(path)
        if scope is None:
            return None

        root_label, relative_path = scope
        versions = self._existing_versions(root_label, relative_path)
        if not versions:
            return None

        candidate = None
        if before_timestamp is not None:
            for version_path in reversed(versions):
                if version_path.stat().st_mtime <= before_timestamp:
                    candidate = version_path
                    break
        if candidate is None:
            candidate = versions[-1]

        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(candidate, path)
        cache_key = f"{root_label}:{relative_path.as_posix()}"
        self._hash_cache[cache_key] = self._hash_file(path)
        return path

    def restore_many(self, paths: Iterable[str | Path], *, before_timestamp: float | None = None) -> list[str]:
        restored: list[str] = []
        for source_path in paths:
            restored_path = self.restore_file(source_path, before_timestamp=before_timestamp)
            if restored_path is not None:
                restored.append(str(restored_path))
        return restored

    def list_versions(self, source_path: str | Path) -> list[dict[str, object]]:
        scope = self._resolve_scope(source_path)
        if scope is None:
            return []

        root_label, relative_path = scope
        versions = self._existing_versions(root_label, relative_path)
        payload: list[dict[str, object]] = []
        for version_path in versions:
            payload.append(
                {
                    "path": str(version_path),
                    "size": version_path.stat().st_size,
                    "modified": version_path.stat().st_mtime,
                }
            )
        return payload
