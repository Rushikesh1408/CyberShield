from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Iterable

from .backup import VersionedSnapshotManager
from .dna import DigitalDNAStore, compare_dna
from .monitor import RealTimeMonitor, default_monitor_paths
from .network_isolation import isolate_network
from .restore import RestoreManager
from .scoring import calculate_threat_score


class CyberShieldPipeline:
    """Orchestrates monitoring, scoring, backup, restore, and containment flow."""

    def __init__(
        self,
        *,
        watch_paths: Iterable[str | Path] | None = None,
        backup_root: str | Path | None = None,
        threat_score_trigger: int = 70,
        network_mode: str = "safe",
        max_file_activity: int = 200,
        max_dna_mismatch: int = 20,
    ) -> None:
        paths = list(watch_paths) if watch_paths is not None else default_monitor_paths()
        unique_paths: list[Path] = []
        seen: set[str] = set()
        for value in paths:
            resolved = Path(value).resolve()
            key = str(resolved).lower()
            if key in seen:
                continue
            seen.add(key)
            unique_paths.append(resolved)

        if not unique_paths:
            raise ValueError("watch_paths cannot be empty")

        if network_mode not in {"safe", "aggressive"}:
            raise ValueError("network_mode must be either 'safe' or 'aggressive'")

        self.watch_paths = unique_paths
        self.backup_root = Path(backup_root or (Path.cwd() / "backup")).resolve()
        self.backup_root.mkdir(parents=True, exist_ok=True)

        self.threat_score_trigger = max(1, int(threat_score_trigger))
        self.network_mode = network_mode
        self.max_file_activity = max(1, int(max_file_activity))
        self.max_dna_mismatch = max(1, int(max_dna_mismatch))

        self.monitor = RealTimeMonitor(watch_paths=self.watch_paths, on_event=self._on_monitor_event)
        self.snapshot_manager = VersionedSnapshotManager(self.watch_paths, self.backup_root)
        self.restore_manager = RestoreManager(self.watch_paths, self.backup_root)
        self.dna_store = DigitalDNAStore()

        self._lock = threading.Lock()
        self._dna_baseline: dict[str, dict[str, Any]] = {}
        self._dna_mismatch_count = 0
        self._isolation_active = False
        self._last_assessment: dict[str, Any] | None = None

    def start(self) -> bool:
        return self.monitor.start()

    def stop(self) -> bool:
        return self.monitor.stop()

    def register_file(self, source_path: str | Path, *, snapshot: bool = True) -> dict[str, Any]:
        path = Path(source_path).resolve()
        if not path.exists() or not path.is_file():
            return {
                "registered": False,
                "source_path": str(path),
                "reason": "file_not_found",
            }

        baseline = self._set_dna_baseline(path)
        snapshot_payload = None
        if snapshot:
            snapshot_payload = self.snapshot_manager.create_snapshot(path, force=True)

        return {
            "registered": baseline is not None,
            "source_path": str(path),
            "baseline": baseline,
            "snapshot": snapshot_payload,
        }

    def register_many(self, paths: Iterable[str | Path], *, snapshot: bool = True) -> dict[str, Any]:
        registered = 0
        failed = 0
        items: list[dict[str, Any]] = []
        for value in paths:
            result = self.register_file(value, snapshot=snapshot)
            items.append(result)
            if result.get("registered"):
                registered += 1
            else:
                failed += 1
        return {
            "registered": registered,
            "failed": failed,
            "items": items,
        }

    def create_snapshot(self, source_path: str | Path, *, force: bool = False) -> dict[str, Any] | None:
        return self.snapshot_manager.create_snapshot(source_path, force=force)

    def snapshot_folder(self, folder: str | Path | None = None) -> list[dict[str, Any]]:
        return self.snapshot_manager.snapshot_folder(folder)

    def restore_file(
        self,
        source_path: str | Path,
        *,
        version: int | None = None,
        before_timestamp: float | None = None,
    ) -> dict[str, Any] | None:
        result = self.restore_manager.restore_file(
            source_path,
            version=version,
            before_timestamp=before_timestamp,
        )
        if result is None:
            return None

        restored_path = Path(str(result["source_path"]))
        self._set_dna_baseline(restored_path)
        return result

    def restore_many(
        self,
        paths: Iterable[str | Path],
        *,
        version: int | None = None,
        before_timestamp: float | None = None,
    ) -> list[str]:
        restored = self.restore_manager.restore_many(
            paths,
            version=version,
            before_timestamp=before_timestamp,
        )
        for value in restored:
            self._set_dna_baseline(Path(value))
        return restored

    def list_versions(self, source_path: str | Path) -> list[dict[str, Any]]:
        return self.restore_manager.list_versions(source_path)

    def assess_threat(self, *, respond: bool = False) -> dict[str, Any]:
        monitor_snapshot = self.monitor.snapshot()
        score_payload = self._score_from_snapshot(monitor_snapshot)
        score_value = int(score_payload["score"])
        triggered = score_value >= self.threat_score_trigger

        actions: list[dict[str, Any]] = []
        if respond:
            with self._lock:
                should_isolate = triggered and not self._isolation_active

            if should_isolate:
                isolation = isolate_network(mode=self.network_mode)
                actions.append({"type": "network_isolation", "result": isolation})
                with self._lock:
                    self._isolation_active = True
            elif not triggered:
                with self._lock:
                    self._isolation_active = False

        with self._lock:
            tracked_files = len(self._dna_baseline)
            dna_mismatch_count = self._dna_mismatch_count

        assessment = {
            "timestamp": time.time(),
            "triggered": triggered,
            "trigger_threshold": self.threat_score_trigger,
            "score": score_value,
            "level": str(score_payload["level"]),
            "status": "ATTACK_DETECTED" if triggered else "SAFE",
            "metrics": {
                "file_activity_count": int(monitor_snapshot["file_activity_count"]),
                "file_activity_rate": float(monitor_snapshot["file_activity_rate"]),
                "cpu_usage": float(monitor_snapshot["cpu_usage"]),
                "active_processes": int(monitor_snapshot["active_processes"]),
                "dna_mismatch_count": int(dna_mismatch_count),
                "tracked_files": int(tracked_files),
            },
            "actions": actions,
        }

        with self._lock:
            self._last_assessment = dict(assessment)
        return assessment

    def status(self) -> dict[str, Any]:
        monitor_snapshot = self.monitor.snapshot()
        threat = self.assess_threat(respond=False)
        backup = self.snapshot_manager.status()
        with self._lock:
            last_assessment = dict(self._last_assessment) if self._last_assessment is not None else None

        return {
            "is_running": bool(monitor_snapshot["is_running"]),
            "watch_paths": [str(path) for path in self.watch_paths],
            "backup": backup,
            "threat": threat,
            "last_assessment": last_assessment,
            "network_mode": self.network_mode,
        }

    def run_cycle(self) -> dict[str, Any]:
        return self.assess_threat(respond=True)

    def _score_from_snapshot(self, monitor_snapshot: dict[str, Any]) -> dict[str, int | str]:
        with self._lock:
            dna_mismatch_count = self._dna_mismatch_count

        return calculate_threat_score(
            file_activity_count=int(monitor_snapshot.get("file_activity_count", 0)),
            cpu_usage=float(monitor_snapshot.get("cpu_usage", 0.0)),
            dna_mismatch_count=int(dna_mismatch_count),
            max_file_activity=self.max_file_activity,
            max_dna_mismatch=self.max_dna_mismatch,
        )

    def _set_dna_baseline(self, path: Path) -> dict[str, Any] | None:
        if not path.exists() or not path.is_file():
            return None

        try:
            dna, _ = self.dna_store.generate_if_modified(path)
        except FileNotFoundError:
            return None

        key = str(path.resolve())
        with self._lock:
            self._dna_baseline[key] = dna
        return dict(dna)

    def _on_monitor_event(self, payload: dict[str, Any]) -> None:
        action = str(payload.get("action") or "").lower()
        file_value = str(payload.get("file") or "").strip()
        if action not in {"created", "modified", "deleted"} or not file_value:
            return

        path = Path(file_value).resolve()
        key = str(path)

        if action == "deleted":
            with self._lock:
                self._dna_baseline.pop(key, None)
            return

        if not path.exists() or not path.is_file():
            return

        try:
            current_dna, updated = self.dna_store.generate_if_modified(path)
        except FileNotFoundError:
            return

        with self._lock:
            previous_dna = self._dna_baseline.get(key)
            if updated and previous_dna is not None:
                if compare_dna(previous_dna, current_dna) == "MISMATCH":
                    self._dna_mismatch_count += 1
            self._dna_baseline[key] = current_dna

        force_snapshot = action == "created"
        self.snapshot_manager.create_snapshot(path, force=force_snapshot)
