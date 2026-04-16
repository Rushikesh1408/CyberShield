from __future__ import annotations

import os
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque

import psutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from backend.backup import BackupManager
from backend.database import Database
from backend.fingerprint import FingerprintManager
from backend.process_killer import ProcessKiller
from backend.services import BackupService
from backend.services import ProcessService
from backend.services import RecoveryService
from backend.services import SafeInterventionService

SUSPICIOUS_EXTENSIONS = {".enc", ".locked", ".encrypted", ".crypt", ".ransom"}
PRE_ATTACK_CPU_THRESHOLD = 70.0
PRE_ATTACK_FILE_RATE_THRESHOLD = 50.0
THREAT_CONFIDENCE_MAX_FILE_RATE = 50.0


@dataclass
class DetectionMetrics:
    files_per_second: float = 0.0
    modifications: int = 0
    accesses: int = 0
    cpu_percent: float = 0.0
    threat_confidence: int = 0
    status: str = "SAFE"


class DetectionEngine:
    def __init__(
        self,
        *,
        monitored_paths: list[str | Path],
        report_file_path: str | Path,
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
        self.process_service = ProcessService()
        self.safe_intervention_service = SafeInterventionService(
            database=self.database,
            process_service=self.process_service,
            backup_service=BackupService(
                monitored_paths=unique_paths,
                backup_root=self.backup_manager.backup_root,
                backup_manager=self.backup_manager,
            ),
            recovery_service=RecoveryService(
                monitored_paths=unique_paths,
                backup_root=self.backup_manager.backup_root,
            ),
        )
        self.report_file_path = Path(report_file_path).resolve()
        self.report_file_path.parent.mkdir(parents=True, exist_ok=True)
        self.observer = Observer()
        self.metrics = DetectionMetrics()
        self.status = "SAFE"
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._sampling_thread: threading.Thread | None = None
        self._initial_backup_thread: threading.Thread | None = None
        self._event_times: Deque[float] = deque(maxlen=5000)
        self._modification_times: Deque[float] = deque(maxlen=5000)
        self._access_times: Deque[float] = deque(maxlen=5000)
        self._folder_modification_times: dict[str, Deque[float]] = {
            str(path): deque(maxlen=5000) for path in self.monitored_paths
        }
        self._touched_paths: set[str] = set()
        self._suspicious_paths: set[str] = set()
        self._attack_active = False
        self._early_warning_active = False
        self._suppress_events_until = 0.0
        self._last_attack_at = 0.0
        self._last_cpu = 0.0
        self._cpu_history: Deque[float] = deque(maxlen=30)
        self._windows_utility_cpu: float | None = None
        self._cpu_raw_blend = 0.7
        self._threat_confidence = 0
        self.is_monitoring = False
        psutil.cpu_percent(interval=None)

    def log_event(
        self,
        *,
        event: str,
        file_path: str = "",
        action: str = "none",
        event_type: str = "info",
        cpu_usage: float | None = None,
        file_rate: float | None = None,
        extra: dict[str, object] | None = None,
    ) -> None:
        if file_rate is None:
            now = time.time()
            with self._lock:
                file_rate = float(sum(1 for event_time in self._event_times if event_time >= now - 1.0))

        payload: dict[str, object] = {
            "event": event,
            "file_name": os.path.basename(file_path) if file_path else "",
            "file_path": file_path,
            "cpu_usage": round(float(self._last_cpu if cpu_usage is None else cpu_usage), 2),
            "file_rate": round(float(file_rate), 2),
            "action": action,
            "event_type": event_type,
        }
        if extra:
            payload.update(extra)

        self.database.log_event(payload)

    def start(self) -> bool:
        if self.is_monitoring:
            return False

        handler = _EventHandler(self)
        scheduled_paths: list[str] = []
        for monitored_path in self.monitored_paths:
            if monitored_path.exists() and monitored_path.is_dir():
                self.observer.schedule(handler, str(monitored_path), recursive=True)
                scheduled_paths.append(str(monitored_path))
        if not scheduled_paths:
            raise RuntimeError("No monitored paths exist for watchdog observer")

        self.observer.start()
        self._stop_event.clear()
        self._sampling_thread = threading.Thread(target=self._sampling_loop, name="cybershield-sampler", daemon=True)
        self._sampling_thread.start()
        self.is_monitoring = True
        self.log_event(
            event="monitoring_started",
            action="none",
            event_type="info",
            cpu_usage=self._last_cpu,
            file_rate=0.0,
            extra={"paths": scheduled_paths},
        )

        # Run initial snapshot in background so monitoring can start immediately.
        self._initial_backup_thread = threading.Thread(
            target=self._run_initial_snapshot,
            name="cybershield-initial-backup",
            daemon=True,
        )
        self._initial_backup_thread.start()
        return True

    def stop(self) -> bool:
        if not self.is_monitoring:
            return False

        self._stop_event.set()
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join(timeout=3)
        if self._sampling_thread and self._sampling_thread.is_alive():
            self._sampling_thread.join(timeout=3)

        # Log only after observer/thread shutdown is complete.
        self.is_monitoring = False
        self.log_event(
            event="monitoring_stopped",
            action="none",
            event_type="info",
            cpu_usage=self._last_cpu,
            file_rate=0.0,
            extra={"paths": [str(path) for path in self.monitored_paths]},
        )
        return True

    def record_event(self, event_type: str, src_path: str, dest_path: str | None = None) -> None:
        now = time.time()
        if now < self._suppress_events_until:
            return

        raw_src_path = src_path
        path = Path(src_path).resolve()
        dest = Path(dest_path).resolve() if dest_path else None
        monitored_root = self._resolve_monitored_root(path)
        monitored_dest_root = self._resolve_monitored_root(dest) if dest is not None else None
        with self._lock:
            self._event_times.append(now)
            self._access_times.append(now)
            if event_type in {"modified", "created", "moved", "deleted"}:
                self._modification_times.append(now)
                if monitored_root is not None:
                    self._folder_modification_times[monitored_root].append(now)
            self._touched_paths.add(str(path))
            if dest is not None:
                self._touched_paths.add(str(dest))
                if event_type in {"moved", "created", "modified"} and monitored_dest_root is not None:
                    self._folder_modification_times[monitored_dest_root].append(now)
            if path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                self._suspicious_paths.add(str(path))
            if dest is not None and dest.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                self._suspicious_paths.add(str(dest))
            current_file_rate = float(sum(1 for event_time in self._event_times if event_time >= now - 1.0))

        event_name_map = {
            "created": "file_created",
            "modified": "file_modified",
            "moved": "file_renamed",
            "deleted": "file_deleted",
        }
        self.log_event(
            event=event_name_map.get(event_type, "file_event"),
            file_path=raw_src_path,
            action="none",
            event_type="info",
            cpu_usage=self._last_cpu,
            file_rate=current_file_rate,
            extra={
                "watchdog_event": event_type,
                "destination_path": dest_path or "",
            },
        )

        if event_type in {"created", "modified"} and path.exists() and path.is_file():
            self.backup_manager.backup_file(path)
        elif event_type == "moved" and dest is not None and dest.exists() and dest.is_file():
            self.backup_manager.backup_file(dest)

    def _sampling_loop(self) -> None:
        while not self._stop_event.wait(1.0):
            try:
                self._sample()
            except (RuntimeError, ValueError, OSError, psutil.Error) as error:
                self.database.insert_log(
                    "error",
                    "Sampling loop error",
                    metadata={"error": str(error)},
                )

    def _run_initial_snapshot(self) -> None:
        try:
            results = self.backup_manager.snapshot_folder()
            self.log_event(
                event="initial_backup_completed",
                action="none",
                event_type="info",
                cpu_usage=self._last_cpu,
                file_rate=0.0,
                extra={"created_files": len(results)},
            )
        except (OSError, RuntimeError, ValueError) as snapshot_error:
            self.log_event(
                event="initial_backup_failed",
                action="none",
                event_type="warning",
                cpu_usage=self._last_cpu,
                file_rate=0.0,
                extra={"error": str(snapshot_error)},
            )

    def generate_attack_report(self, data: dict[str, Any]) -> str:
        process_action = (
            "Active Threat Neutralization executed"
            if data.get("process_terminated")
            else "Active Threat Neutralization attempted"
        )
        restore_action = (
            "Automatic System Recovery restored files"
            if int(data.get("files_restored", 0)) > 0
            else "Automatic System Recovery not required"
        )
        files_affected = int(data.get("files_affected", 0) or 0)
        files_restored = int(data.get("files_restored", 0) or 0)
        files_irrecoverable = int(
            data.get("files_irrecoverable", max(files_affected - files_restored, 0)) or 0
        )
        if files_affected <= 0 or (files_restored >= files_affected and files_irrecoverable <= 0):
            status_text = "✔ No data loss"
        elif files_restored > 0:
            status_text = (
                f"⚠ Partial recovery ({files_restored}/{files_affected} files restored, "
                f"{files_irrecoverable} unrecoverable)"
            )
        else:
            status_text = f"✖ Recovery failed ({files_irrecoverable or files_affected} files unrecoverable)"
        report_text = (
            "--- CyberShield Attack Report ---\n\n"
            f"Time: {data.get('timestamp')}\n"
            f"Attack Type: {data.get('attack_type')}\n"
            f"Process: {data.get('process_name')}\n"
            f"CPU Usage: {data.get('cpu_usage')}%\n"
            f"Files Affected: {data.get('files_affected')}\n\n"
            "Actions Taken:\n\n"
            f"{process_action}\n\n"
            f"{restore_action}\n\n"
            "Status:\n"
            "✔ System secured\n"
        )

        self.report_file_path.write_text(report_text, encoding="utf-8")
        return str(self.report_file_path)

    @staticmethod
    def send_alert(phone: str, message: str) -> None:
        print(f"ALERT sent to {phone}: {message}")

    def _run_attack_followups(self, payload: dict[str, Any]) -> None:
        report_path = self.generate_attack_report(payload)
        self.log_event(
            event="attack_report_generated",
            file_path=report_path,
            action="none",
            event_type="info",
            cpu_usage=float(payload.get("cpu_usage") or 0.0),
            file_rate=float(payload.get("file_rate") or 0.0),
            extra={
                "attack_type": payload.get("attack_type"),
                "files_affected": int(payload.get("files_affected") or 0),
                "files_recovered": int(payload.get("files_restored") or 0),
                "threat_confidence": int(payload.get("threat_confidence") or 0),
            },
        )

        emergency_phone = self.database.get_setting("emergency_contact", "")
        if not emergency_phone:
            return

        alert_message = (
            "CyberShield Emergency Alert\n\n"
            "Ransomware attack detected!\n"
            "Active Threat Neutralization and Automatic System Recovery executed.\n\n"
            f"Time: {payload.get('timestamp')}"
        )
        self.send_alert(emergency_phone, alert_message)
        self.database.insert_alert(
            status="SENT",
            title="Emergency SOS Triggered",
            details=f"Emergency alert sent to {emergency_phone} after ransomware detection.",
            severity="critical",
            fingerprint_match=None,
        )
        self.log_event(
            event="emergency_alert_sent",
            action="none",
            event_type="critical",
            cpu_usage=float(payload.get("cpu_usage") or 0.0),
            file_rate=float(payload.get("file_rate") or 0.0),
            extra={"phone": emergency_phone},
        )

    def _trigger_attack_followups(self, payload: dict[str, Any]) -> None:
        thread = threading.Thread(
            target=self._run_attack_followups,
            args=(payload,),
            name="cybershield-attack-followup",
            daemon=True,
        )
        thread.start()

    def _sample(self) -> None:
        now = time.time()
        with self._lock:
            event_times = self._trimmed(self._event_times, now, 1.0)
            modification_times = self._trimmed(self._modification_times, now, 5.0)
            access_times = self._trimmed(self._access_times, now, 5.0)
            folder_modification_counts: dict[str, int] = {}
            for folder_path, times in self._folder_modification_times.items():
                folder_modification_counts[folder_path] = len(self._trimmed(times, now, 5.0))

        cpu_percent = psutil.cpu_percent(interval=None)
        utility_cpu = self._read_windows_cpu_utility()
        with self._lock:
            cpu_for_detection = utility_cpu if utility_cpu is not None else cpu_percent
            self._last_cpu = cpu_for_detection
            self._cpu_history.append(cpu_for_detection)
            self._windows_utility_cpu = utility_cpu
        files_per_second = float(len(event_times))
        modifications = len(modification_times)
        accesses = len(access_times)
        folders_with_activity = sum(1 for count in folder_modification_counts.values() if count > 0)
        folders_with_spike = sum(1 for count in folder_modification_counts.values() if count >= 5)

        status = "SAFE"
        signals = 0
        rapid_modifications = files_per_second >= 4 or modifications >= 6
        suspicious_extension = bool(self._suspicious_paths)
        cross_folder_spike = modifications > 20 and folders_with_activity >= 2
        cross_folder_ramp = folders_with_spike >= 2 and modifications >= 10
        high_access_rate = accesses >= 10
        cpu_spike = cpu_for_detection >= 70.0
        pre_attack_signal = (
            cpu_for_detection > PRE_ATTACK_CPU_THRESHOLD
            and files_per_second > PRE_ATTACK_FILE_RATE_THRESHOLD
        )

        cpu_usage = cpu_for_detection
        file_rate = files_per_second
        max_file_rate = THREAT_CONFIDENCE_MAX_FILE_RATE

        cpu_score = min(cpu_usage / 100, 1)
        file_score = min(file_rate / max_file_rate, 1)
        ext_score = 1 if suspicious_extension else 0

        confidence = (cpu_score + file_score + ext_score) / 3
        confidence_percent = int(confidence * 100)
        self._threat_confidence = confidence_percent

        if rapid_modifications:
            signals += 1
        if suspicious_extension:
            signals += 1
        if cross_folder_spike or cross_folder_ramp:
            signals += 2
        if high_access_rate:
            signals += 1
        if cpu_spike:
            signals += 1

        full_detection = (
            cross_folder_spike
            or cross_folder_ramp
            or (suspicious_extension and signals >= 2)
            or (not suspicious_extension and signals >= 3)
        )

        if pre_attack_signal and not self._early_warning_active:
            self._early_warning_active = True
            self.status = "UNDER_ATTACK"
            self.database.insert_alert(
                "UNDER_ATTACK",
                "Early Threat Detection",
                (
                    "Threshold-based early warning using behavioral anomalies "
                    "such as CPU spikes and high file access rate."
                ),
                severity="medium",
            )
            self.log_event(
                event="early_threat_detection",
                action="flagged",
                event_type="warning",
                cpu_usage=cpu_for_detection,
                file_rate=files_per_second,
                extra={
                    "modifications": modifications,
                    "accesses": accesses,
                    "threat_confidence": confidence_percent,
                },
            )
        elif not pre_attack_signal:
            self._early_warning_active = False

        if full_detection and (rapid_modifications or high_access_rate):
            status = "UNDER_ATTACK"
            self._last_attack_at = now
            self._handle_attack(
                files_per_second=files_per_second,
                modifications=modifications,
                accesses=accesses,
                cpu_percent=cpu_for_detection,
                suspicious_extension=suspicious_extension,
                folder_modification_counts=folder_modification_counts,
            )
        else:
            self.status = "UNDER_ATTACK" if self._early_warning_active else "SAFE"

        self.metrics = DetectionMetrics(
            files_per_second=round(files_per_second, 2),
            modifications=modifications,
            accesses=accesses,
            cpu_percent=round(cpu_for_detection, 2),
            threat_confidence=confidence_percent,
            status=self.status if status == "SAFE" else status,
        )
        self.database.insert_metrics(
            self.metrics.files_per_second,
            self.metrics.modifications,
            self.metrics.accesses,
            self.metrics.cpu_percent,
            self.metrics.status,
        )

    def _display_cpu(self) -> tuple[float, float]:
        with self._lock:
            history = list(self._cpu_history)
            last_cpu = self._last_cpu
            utility_cpu = self._windows_utility_cpu

        if not history:
            raw = utility_cpu if utility_cpu is not None else last_cpu
            return raw, raw

        raw = utility_cpu if utility_cpu is not None else history[-1]
        rolling_average = sum(history) / len(history)
        calibrated = (self._cpu_raw_blend * raw) + ((1.0 - self._cpu_raw_blend) * rolling_average)
        calibrated = max(0.0, min(100.0, calibrated))
        return raw, calibrated

    def _resolve_monitored_root(self, path: Path | None) -> str | None:
        if path is None:
            return None
        resolved = path.resolve()
        for monitored_path in self.monitored_paths:
            try:
                resolved.relative_to(monitored_path)
                return str(monitored_path)
            except ValueError:
                continue
        return None

    def _read_windows_cpu_utility(self) -> float | None:
        if os.name != "nt":
            return None
        try:
            command = (
                "(Get-Counter '\\Processor Information(_Total)\\% Processor Utility')."
                "CounterSamples[0].CookedValue"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=1.5,
                check=False,
            )
            if result.returncode != 0:
                return None
            value = float((result.stdout or "").strip().splitlines()[-1])
            return max(0.0, min(100.0, value))
        except (OSError, ValueError, IndexError, subprocess.SubprocessError):
            return None

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
        folder_modification_counts: dict[str, int] | None = None,
    ) -> None:
        if self._attack_active:
            self.status = "UNDER_ATTACK"
            return

        self._attack_active = True
        self.status = "UNDER_ATTACK"
        suspected_process_name = self._infer_process_name()
        fingerprint = self.fingerprint_manager.create(
            process_name=suspected_process_name,
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
        if folder_modification_counts:
            active_folders = [path for path, count in folder_modification_counts.items() if count > 0]
            spike_folders = [path for path, count in folder_modification_counts.items() if count >= 5]
            if len(active_folders) >= 2 and modifications > 20:
                self.database.insert_alert(
                    "UNDER_ATTACK",
                    "Cross-folder ransomware spread detected",
                    (
                        f"Rapid file changes across multiple folders detected: {len(active_folders)} folders active "
                        f"with {modifications} modifications in the last 5 seconds."
                    ),
                    severity="critical",
                    fingerprint_match=fingerprint["signature_hash"],
                )
            elif len(spike_folders) >= 2 and modifications >= 10:
                self.database.insert_alert(
                    "UNDER_ATTACK",
                    "Cross-folder ransomware spread suspected",
                    (
                        f"Multiple folders are spiking simultaneously: {len(spike_folders)} folders with "
                        f"rapid modification bursts in the last 5 seconds."
                    ),
                    severity="high",
                    fingerprint_match=fingerprint["signature_hash"],
                )
        self.log_event(
            event="attack_detected",
            action="flagged",
            event_type="critical",
            cpu_usage=cpu_percent,
            file_rate=files_per_second,
            extra={
                "modifications": modifications,
                "accesses": accesses,
                "suspicious_extension": suspicious_extension,
            },
        )

        intervention_result = self.safe_intervention_service.handle_attack(
            monitored_paths=self.monitored_paths,
            lookback_seconds=5.0,
            cpu_threshold=PRE_ATTACK_CPU_THRESHOLD,
            terminate_threshold=PRE_ATTACK_CPU_THRESHOLD,
            recheck_delay_seconds=1.5,
        )
        terminated_processes = intervention_result.get("confirmed_processes")
        terminated_process_name = ""
        if isinstance(terminated_processes, list) and terminated_processes:
            first_confirmed = terminated_processes[0]
            if isinstance(first_confirmed, dict):
                terminated_process_name = str(first_confirmed.get("name") or "")

        if terminated_process_name:
            self.log_event(
                event="active_threat_neutralization",
                action="contained",
                event_type="critical",
                cpu_usage=cpu_percent,
                file_rate=files_per_second,
                extra={
                    "process_name": terminated_process_name,
                    "processes": terminated_processes,
                    "action_taken": intervention_result.get("action_taken", []),
                },
            )
            self.database.insert_alert(
                "UNDER_ATTACK",
                "Active Threat Neutralization",
                f"Contained suspicious process activity for {terminated_process_name}.",
                severity="high",
                fingerprint_match=fingerprint["signature_hash"],
            )
            if kill_result is None:
                self.database.insert_log(
                    "warning",
                    "Containment scan completed without a confident process kill",
                    metadata={"target_paths": self._target_paths()},
                )
            else:
                self.database.insert_log(
                    "warning",
                    "Suspicious process terminated",
                    process_name=kill_result.name,
                    metadata={
                        "pid": kill_result.pid,
                        "cmdline": kill_result.cmdline,
                        "reason": kill_result.reason,
                        "success": kill_result.success,
                        "error": kill_result.error,
                    },
                )
                if kill_result.success:
                    self.database.insert_alert(
                        "UNDER_ATTACK",
                        "Suspicious process killed",
                        f"Terminated process {kill_result.name} (PID {kill_result.pid}).",
                        severity="high",
                        fingerprint_match=fingerprint["signature_hash"],
                    )
                else:
                    failure_reason = kill_result.error or kill_result.reason
                    self.database.insert_alert(
                        "UNDER_ATTACK",
                        "Failed to kill suspicious process",
                        (
                            f"Termination failed for process {kill_result.name} (PID {kill_result.pid}). "
                            f"Reason: {failure_reason}."
                        ),
                        severity="critical",
                        fingerprint_match=fingerprint["signature_hash"],
                    )

        restored_count = int(intervention_result.get("files_recovered") or 0)

        with self._lock:
            suspicious_count = len(self._suspicious_paths)
            touched_count = len(self._touched_paths)

        files_affected = max(modifications, suspicious_count, touched_count)
        self._trigger_attack_followups(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "attack_type": "mass_encryption" if suspicious_extension else "suspicious_activity",
                "process_name": terminated_process_name or suspected_process_name,
                "cpu_usage": round(cpu_percent, 2),
                "files_affected": files_affected,
                "process_terminated": "process_terminated" in intervention_result.get("action_taken", []),
                "files_restored": restored_count,
                "file_rate": round(files_per_second, 2),
                "threat_confidence": self._threat_confidence,
            }
        )

        if restored_count > 0:
            self.log_event(
                event="automatic_system_recovery",
                action="restored",
                event_type="info",
                cpu_usage=cpu_percent,
                file_rate=files_per_second,
                extra={"restored_count": restored_count, "restored": intervention_result.get("files_recovered", [])},
            )
        self._suppress_events_until = time.time() + 2.5
        self._attack_active = False
        self.status = "SAFE"
        self.database.insert_alert(
            "SAFE",
            "System Safe",
            "Automatic System Recovery completed and monitoring returned to safe state.",
            severity="medium",
            fingerprint_match=fingerprint["signature_hash"],
        )
        self.log_event(
            event="system_safe",
            action="restored",
            event_type="info",
            cpu_usage=cpu_percent,
            file_rate=files_per_second,
        )

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
        # Adaptive rolling calibration stays stable across laptops and avoids per-request sampling jitter.
        try:
            live_cpu_raw, live_cpu_calibrated = self._display_cpu()
        except (TypeError, ValueError, ZeroDivisionError):
            live_cpu_raw = self._last_cpu
            live_cpu_calibrated = self._last_cpu

        metrics = self.metrics
        display_cpu = max(live_cpu_calibrated, metrics.cpu_percent)
        return {
            "status": self.status,
            "confidence": self._threat_confidence,
            "is_monitoring": self.is_monitoring,
            "monitored_paths": [str(path) for path in self.monitored_paths],
            "metrics": {
                "files_per_second": metrics.files_per_second,
                "modifications": metrics.modifications,
                "accesses": metrics.accesses,
                "cpu_percent": round(display_cpu, 2),
                "cpu_percent_raw": round(live_cpu_raw, 2),
                "cpu_percent_sampled": metrics.cpu_percent,
                "threat_confidence": metrics.threat_confidence,
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
