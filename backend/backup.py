from __future__ import annotations

import hashlib
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


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
        self._lock = threading.Lock()
        self._hash_cache: dict[str, str] = {}
        self._root_labels = self._build_root_labels(self.source_roots)

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
            version_number = len(versions) + 1
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
            return BackupResult(str(path), str(destination), version_number)

    def snapshot_folder(self, folder: str | Path | None = None) -> list[BackupResult]:
        roots = [Path(folder).resolve()] if folder else self.source_roots
        results: list[BackupResult] = []
        for root in roots:
            if not root.exists() or not root.is_dir():
                continue
            for file_path in root.rglob("*"):
                if file_path.is_file():
                    result = self.backup_file(file_path, force=True)
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
