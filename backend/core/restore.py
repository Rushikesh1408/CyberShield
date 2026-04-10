from __future__ import annotations

import re
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


_VERSION_PATTERN = re.compile(r"_v(\d+)$")


@dataclass(frozen=True)
class RestoreResult:
    source_path: str
    backup_path: str
    version: int


class RestoreManager:
    def __init__(self, source_roots: Iterable[str | Path], backup_root: str | Path) -> None:
        normalized_roots = [Path(path).resolve() for path in source_roots]
        unique_roots: list[Path] = []
        seen: set[str] = set()
        for root in normalized_roots:
            key = str(root).lower()
            if key in seen:
                continue
            seen.add(key)
            unique_roots.append(root)

        if not unique_roots:
            raise ValueError("source_roots cannot be empty")

        self.source_roots = unique_roots
        self.backup_root = Path(backup_root).resolve()
        self._lock = threading.Lock()
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

    def _resolve_scope(self, source_path: str | Path) -> tuple[str, Path] | None:
        resolved = Path(source_path).resolve()
        for root in self.source_roots:
            try:
                relative = resolved.relative_to(root)
                label = self._root_labels[str(root)]
                return label, relative
            except ValueError:
                continue
        return None

    @staticmethod
    def _extract_version(path: Path) -> int | None:
        match = _VERSION_PATTERN.search(path.stem)
        if not match:
            return None
        try:
            return int(match.group(1))
        except (TypeError, ValueError):
            return None

    def _existing_versions(self, root_label: str, relative_path: Path) -> list[tuple[int, Path]]:
        backup_dir = self.backup_root / root_label / relative_path.parent
        if not backup_dir.exists():
            return []

        pattern = f"{relative_path.stem}_v*{relative_path.suffix}"
        versions: list[tuple[int, Path]] = []
        for backup_file in backup_dir.glob(pattern):
            version = self._extract_version(backup_file)
            if version is None:
                continue
            versions.append((version, backup_file))

        versions.sort(key=lambda item: item[0])
        return versions

    def list_versions(self, source_path: str | Path) -> list[dict[str, Any]]:
        scope = self._resolve_scope(source_path)
        if scope is None:
            return []

        root_label, relative_path = scope
        versions = self._existing_versions(root_label, relative_path)
        payload: list[dict[str, Any]] = []
        for version, backup_file in versions:
            payload.append(
                {
                    "version": int(version),
                    "path": str(backup_file),
                    "size": int(backup_file.stat().st_size),
                    "modified": float(backup_file.stat().st_mtime),
                }
            )
        return payload

    def _select_candidate(
        self,
        versions: list[tuple[int, Path]],
        *,
        version: int | None,
        before_timestamp: float | None,
    ) -> tuple[int, Path] | None:
        if not versions:
            return None

        if version is not None:
            for current_version, backup_file in versions:
                if current_version == int(version):
                    return current_version, backup_file
            return None

        if before_timestamp is not None:
            for current_version, backup_file in reversed(versions):
                if backup_file.stat().st_mtime <= before_timestamp:
                    return current_version, backup_file
            return None

        return versions[-1]

    def restore_file(
        self,
        source_path: str | Path,
        *,
        version: int | None = None,
        before_timestamp: float | None = None,
    ) -> dict[str, Any] | None:
        scope = self._resolve_scope(source_path)
        if scope is None:
            return None

        root_label, relative_path = scope
        with self._lock:
            versions = self._existing_versions(root_label, relative_path)
            candidate = self._select_candidate(
                versions,
                version=version,
                before_timestamp=before_timestamp,
            )
            if candidate is None:
                return None

            selected_version, backup_file = candidate
            destination = Path(source_path).resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup_file, destination)

        return RestoreResult(
            source_path=str(destination),
            backup_path=str(backup_file),
            version=int(selected_version),
        ).__dict__.copy()

    def restore_many(
        self,
        paths: Iterable[str | Path],
        *,
        version: int | None = None,
        before_timestamp: float | None = None,
    ) -> list[str]:
        restored: list[str] = []
        for source_path in paths:
            result = self.restore_file(
                source_path,
                version=version,
                before_timestamp=before_timestamp,
            )
            if result is not None:
                restored.append(str(result["source_path"]))
        return restored
