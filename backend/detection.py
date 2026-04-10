from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque

import psutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from backend.backup import BackupManager
from backend.database import Database
from backend.fingerprint import FingerprintManager
from backend.process_killer import ProcessKiller

SUSPICIOUS_EXTENSIONS = {".enc", ".locked", ".encrypted", ".crypt", ".ransom"}


@dataclass
class DetectionMetrics:
    files_per_second: float = 0.0
    modifications: int = 0
    accesses: int = 0
    cpu_percent: float = 0.0
    status: str = "SAFE"


class DetectionEngine:
    def __init__(
        self,
        *,
        monitored_paths: list[str | Path],
        backup_manager: BackupManager,
        database: Database,
        fingerprint_manager: FingerprintManager,
        process_killer: ProcessKiller,
    ) -> None:
        unique_paths: list[Path] = []
        seen: set[str] = set()
        for monitored_path in monitored_paths:
            resolved = Path(monitored_path).resolve()
            key = str(resolved).lower()
            if key not in seen:
                unique_paths.append(resolved)
                seen.add(key)
        if not unique_paths:
            raise ValueError("monitored_paths cannot be empty")

        self.monitored_paths = unique_paths
        self.backup_manager = backup_manager
        self.database = database
        self.fingerprint_manager = fingerprint_manager
        self.process_killer = process_killer
        self.observer = Observer()
        self.metrics = DetectionMetrics()
        self.status = "SAFE"
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._sampling_thread: threading.Thread | None = None
        self._event_times: Deque[float] = deque(maxlen=5000)
        self._modification_times: Deque[float] = deque(maxlen=5000)
        self._access_times: Deque[float] = deque(maxlen=5000)
        self._touched_paths: set[str] = set()
        self._suspicious_paths: set[str] = set()
        self._attack_active = False
        self._early_warning_active = False
        self._suppress_events_until = 0.0
        self._last_attack_at = 0.0
        self._last_cpu = 0.0
        psutil.cpu_percent(interval=None)

    def start(self) -> None:
        handler = _EventHandler(self)
        scheduled_paths: list[str] = []
        for monitored_path in self.monitored_paths:
            if monitored_path.exists() and monitored_path.is_dir():
                self.observer.schedule(handler, str(monitored_path), recursive=True)
                scheduled_paths.append(str(monitored_path))
        if not scheduled_paths:
            raise RuntimeError("No monitored paths exist for watchdog observer")

        self.backup_manager.snapshot_folder()
        self.observer.start()
        self._stop_event.clear()
        self._sampling_thread = threading.Thread(target=self._sampling_loop, name="cybershield-sampler", daemon=True)
        self._sampling_thread.start()
        self.database.insert_log(
            "info",
            "Monitoring started",
            metadata={"paths": scheduled_paths},
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join(timeout=3)
        if self._sampling_thread and self._sampling_thread.is_alive():
            self._sampling_thread.join(timeout=3)
        self.database.insert_log(
            "info",
            "Monitoring stopped",
            metadata={"paths": [str(path) for path in self.monitored_paths]},
        )

    def record_event(self, event_type: str, src_path: str, dest_path: str | None = None) -> None:
        now = time.time()
        if now < self._suppress_events_until:
            return

        path = Path(src_path).resolve()
        dest = Path(dest_path).resolve() if dest_path else None
        with self._lock:
            self._event_times.append(now)
            self._access_times.append(now)
            if event_type in {"modified", "created", "moved", "deleted"}:
                self._modification_times.append(now)
            self._touched_paths.add(str(path))
            if dest is not None:
                self._touched_paths.add(str(dest))
            if path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                self._suspicious_paths.add(str(path))
            if dest is not None and dest.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                self._suspicious_paths.add(str(dest))

        if event_type in {"created", "modified"} and path.exists() and path.is_file():
            self.backup_manager.backup_file(path)
        elif event_type == "moved" and dest is not None and dest.exists() and dest.is_file():
            self.backup_manager.backup_file(dest)

    def _sampling_loop(self) -> None:
        while not self._stop_event.wait(1.0):
            self._sample()

    def _sample(self) -> None:
        now = time.time()
        with self._lock:
            event_times = self._trimmed(self._event_times, now, 1.0)
            modification_times = self._trimmed(self._modification_times, now, 5.0)
            access_times = self._trimmed(self._access_times, now, 5.0)

        cpu_percent = psutil.cpu_percent(interval=None)
        self._last_cpu = cpu_percent
        files_per_second = float(len(event_times))
        modifications = len(modification_times)
        accesses = len(access_times)

        status = "SAFE"
        signals = 0
        rapid_modifications = files_per_second >= 4 or modifications >= 6
        suspicious_extension = bool(self._suspicious_paths)
        high_access_rate = accesses >= 10
        cpu_spike = cpu_percent >= 70.0
        early_signal = rapid_modifications and cpu_spike

        if rapid_modifications:
            signals += 1
        if suspicious_extension:
            signals += 1
        if high_access_rate:
            signals += 1
        if cpu_spike:
            signals += 1

        full_detection = (suspicious_extension and signals >= 2) or (not suspicious_extension and signals >= 3)

        if early_signal and not self._early_warning_active:
            self._early_warning_active = True
            self.status = "UNDER_ATTACK"
            self.database.insert_alert(
                "UNDER_ATTACK",
                "Early anomaly detected",
                "High CPU and rapid file activity detected in protected directories.",
                severity="medium",
            )
            self.database.insert_log(
                "warning",
                "Early anomaly detected",
                metadata={
                    "files_per_second": files_per_second,
                    "modifications": modifications,
                    "accesses": accesses,
                    "cpu_percent": cpu_percent,
                },
            )
        elif not early_signal:
            self._early_warning_active = False

        if full_detection and (rapid_modifications or high_access_rate):
            status = "UNDER_ATTACK"
            self._last_attack_at = now
            self._handle_attack(
                files_per_second=files_per_second,
                modifications=modifications,
                accesses=accesses,
                cpu_percent=cpu_percent,
                suspicious_extension=suspicious_extension,
            )
        else:
            self.status = "UNDER_ATTACK" if self._early_warning_active else "SAFE"

        self.metrics = DetectionMetrics(
            files_per_second=round(files_per_second, 2),
            modifications=modifications,
            accesses=accesses,
            cpu_percent=round(cpu_percent, 2),
            status=self.status if status == "SAFE" else status,
        )
        self.database.insert_metrics(
            self.metrics.files_per_second,
            self.metrics.modifications,
            self.metrics.accesses,
            self.metrics.cpu_percent,
            self.metrics.status,
        )

    @staticmethod
    def _trimmed(entries: Deque[float], now: float, window: float) -> list[float]:
        while entries and entries[0] < now - window:
            entries.popleft()
        return list(entries)

    def _handle_attack(
        self,
        *,
        files_per_second: float,
        modifications: int,
        accesses: int,
        cpu_percent: float,
        suspicious_extension: bool,
    ) -> None:
        if self._attack_active:
            self.status = "UNDER_ATTACK"
            return

        self._attack_active = True
        self.status = "UNDER_ATTACK"
        fingerprint = self.fingerprint_manager.create(
            process_name=self._infer_process_name(),
            file_extension=self._infer_extension(),
            modification_rate=files_per_second,
            access_rate=float(accesses),
            cpu_spike=cpu_percent,
        )
        similar = self.fingerprint_manager.compare(fingerprint)
        if similar is not None:
            self.database.insert_alert(
                "UNDER_ATTACK",
                "Similar attack detected",
                "Attack pattern matches a previously stored fingerprint.",
                severity="high",
                fingerprint_match=similar.get("signature_hash"),
            )
        self.fingerprint_manager.store(fingerprint)
        self.database.insert_alert(
            "UNDER_ATTACK",
            "Ransomware behavior detected",
            "Rapid malicious file activity detected in protected directories.",
            severity="critical",
            fingerprint_match=fingerprint["signature_hash"],
        )
        self.database.insert_log(
            "warning",
            "Attack detected",
            metadata={
                "files_per_second": files_per_second,
                "modifications": modifications,
                "accesses": accesses,
                "cpu_percent": cpu_percent,
                "suspicious_extension": suspicious_extension,
            },
        )

        kill_result = self.process_killer.scan_and_kill(
            self._target_paths(),
            reason="ransomware-like file activity",
        )
        if kill_result is not None:
            self.database.insert_log(
                "warning",
                "Suspicious process terminated",
                process_name=kill_result.name,
                metadata={
                    "pid": kill_result.pid,
                    "cmdline": kill_result.cmdline,
                    "reason": kill_result.reason,
                    "success": kill_result.success,
                },
            )
            self.database.insert_alert(
                "UNDER_ATTACK",
                "Suspicious process killed",
                f"Terminated process {kill_result.name} (PID {kill_result.pid}).",
                severity="high",
                fingerprint_match=fingerprint["signature_hash"],
            )

        restored = self.backup_manager.restore_many(
            self._restorable_paths(),
            before_timestamp=self._last_attack_at,
        )
        if restored:
            self.database.insert_log(
                "info",
                "Files restored from backup",
                metadata={"restored_count": len(restored), "paths": restored},
            )
        self._cleanup_suspicious_files()
        self._suppress_events_until = time.time() + 2.5
        self._attack_active = False
        self.status = "SAFE"
        self.database.insert_alert(
            "SAFE",
            "Recovery completed",
            "Files restored and monitoring returned to safe state.",
            severity="medium",
            fingerprint_match=fingerprint["signature_hash"],
        )
        self.database.insert_log("info", "Recovery completed")

    def _restorable_paths(self) -> list[str]:
        with self._lock:
            return sorted(
                path for path in self._touched_paths if Path(path).suffix.lower() not in SUSPICIOUS_EXTENSIONS
            )

    def _cleanup_suspicious_files(self) -> None:
        with self._lock:
            paths = list(self._suspicious_paths)
            self._suspicious_paths.clear()
        for path_string in paths:
            path = Path(path_string)
            try:
                if path.exists() and path.is_file() and self._is_monitored_path(path):
                    path.unlink()
            except (OSError, ValueError):
                continue

    def _infer_extension(self) -> str:
        with self._lock:
            for path_string in reversed(list(self._touched_paths)):
                extension = Path(path_string).suffix.lower()
                if extension:
                    return extension
        return ".unknown"

    def _infer_process_name(self) -> str:
        process, _ = self.process_killer.find_suspicious_process(self._target_paths())
        if process is None:
            return "unknown"
        try:
            return process.name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "unknown"

    def _target_paths(self) -> list[str]:
        return [str(path) for path in self.monitored_paths]

    def _is_monitored_path(self, path: Path) -> bool:
        resolved = path.resolve()
        for monitored_path in self.monitored_paths:
            try:
                resolved.relative_to(monitored_path)
                return True
            except ValueError:
                continue
        return False

    def snapshot(self) -> dict[str, object]:
        metrics = self.metrics
        return {
            "status": self.status,
            "monitored_paths": [str(path) for path in self.monitored_paths],
            "metrics": {
                "files_per_second": metrics.files_per_second,
                "modifications": metrics.modifications,
                "accesses": metrics.accesses,
                "cpu_percent": metrics.cpu_percent,
                "status": metrics.status,
            },
            "alerts": self.database.fetch_alerts(20),
            "logs": self.database.fetch_logs(50),
            "fingerprints": self.database.fetch_fingerprints(),
        }


class _EventHandler(FileSystemEventHandler):
    def __init__(self, engine: DetectionEngine) -> None:
        self.engine = engine

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.engine.record_event("created", event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.engine.record_event("modified", event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.engine.record_event("moved", event.src_path, getattr(event, "dest_path", None))

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.engine.record_event("deleted", event.src_path)
