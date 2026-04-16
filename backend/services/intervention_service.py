from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from backend.database import Database
from backend.core.network_isolation import isolate_network

from .backup_service import BackupService
from .detection_service import DetectionService
from .forensic_service import ForensicService
from .process_service import ProcessService
from .recovery_service import RecoveryService


class SafeInterventionService:
    def __init__(
        self,
        *,
        database: Database,
        detection_service: DetectionService,
        process_service: ProcessService,
        backup_service: BackupService,
        recovery_service: RecoveryService,
        forensic_service: ForensicService,
    ) -> None:
        self.database = database
        self.detection_service = detection_service
        self.process_service = process_service
        self.backup_service = backup_service
        self.recovery_service = recovery_service
        self.forensic_service = forensic_service
        self.system_state = "SAFE"
        self._lock = threading.Lock()
        self._write_protected_paths: list[Path] = []

    def _log_event(self, event: str, *, action: str, event_type: str, extra: dict[str, object] | None = None) -> None:
        payload: dict[str, object] = {
            "event": event,
            "action": action,
            "event_type": event_type,
            "file_name": "",
            "file_path": "",
            "cpu_usage": 0.0,
            "file_rate": 0.0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if extra:
            payload.update(extra)
        self.database.log_event(payload)

    def emit_alert(self, message: str, *, extra: dict[str, object] | None = None) -> None:
        self.database.insert_alert(
            "UNDER_ATTACK",
            "Early Threat Detection",
            message,
            severity="medium",
        )
        self._log_event("early_threat_detection", action="flagged", event_type="warning", extra=extra)

    @staticmethod
    def _append_action(actions: list[str], action: str) -> None:
        if action not in actions:
            actions.append(action)

    @staticmethod
    def _first_process_name(processes: list[dict[str, object]]) -> str:
        if not processes:
            return ""
        return str(processes[0].get("name") or "")

    def _highest_risk_process(self, detection_result: dict[str, object]) -> dict[str, object] | None:
        suspicious = detection_result.get("suspicious_processes")
        if not isinstance(suspicious, list) or not suspicious:
            return None
        best = max(suspicious, key=lambda item: float(item.get("score") or 0.0))
        return best if isinstance(best, dict) else None

    def _apply_write_protection(self, monitored_paths: Iterable[str | Path]) -> list[str]:
        protected: list[str] = []
        self._write_protected_paths = []
        for value in monitored_paths:
            try:
                root = Path(value).resolve()
            except OSError:
                continue

            if not root.exists() or not root.is_dir():
                continue

            for file_path in root.rglob("*"):
                if not file_path.exists():
                    continue
                try:
                    current_mode = file_path.stat().st_mode
                    os.chmod(file_path, current_mode & ~0o222)
                    self._write_protected_paths.append(file_path)
                    protected.append(str(file_path))
                except OSError:
                    continue
        return protected

    def _release_write_protection(self) -> None:
        for file_path in self._write_protected_paths:
            try:
                current_mode = file_path.stat().st_mode
                os.chmod(file_path, current_mode | 0o200)
            except OSError:
                continue
        self._write_protected_paths = []

    def _detect_within_scope(
        self,
        monitored_paths: Iterable[str | Path] | None,
        cpu_threshold: float,
    ) -> list[dict[str, object]]:
        return self.process_service.detect_suspicious_processes(
            monitored_paths=monitored_paths,
            cpu_threshold=cpu_threshold,
        )

    def _re_evaluate(
        self,
        monitored_paths: Iterable[str | Path] | None,
        cpu_threshold: float,
        previous_pids: set[int],
    ) -> list[dict[str, object]]:
        current = self._detect_within_scope(monitored_paths, cpu_threshold)
        return [process for process in current if int(process.get("pid") or 0) in previous_pids]

    def handle_attack(
        self,
        *,
        monitored_paths: Iterable[str | Path] | None = None,
        detection_context: dict[str, object] | None = None,
        lookback_seconds: float = 5.0,
        cpu_threshold: float = 65.0,
        terminate_threshold: float = 60.0,
        recheck_delay_seconds: float = 1.5,
        generate_forensics: bool = True,
    ) -> dict[str, object]:
        with self._lock:
            attack_start_time = datetime.now(timezone.utc).isoformat()
            if detection_context is None:
                detection_context = self.detection_service.calculate_detection(
                    monitored_paths=monitored_paths,
                    cpu_usage=0.0,
                    file_activity_rate=0.0,
                    dna_mismatch_count=0,
                )
            detected_processes = self._detect_within_scope(monitored_paths, cpu_threshold)
            if detected_processes:
                detection_context["suspicious_processes"] = detected_processes
            high_risk_process = self._highest_risk_process(detection_context)
            if high_risk_process is not None:
                detection_context["process_pid"] = int(high_risk_process.get("pid") or 0)

            threat_score = int(detection_context.get("score") or 0)
            confidence = float(detection_context.get("confidence") or 0.0)
            threat_level = str(detection_context.get("level") or "LOW")
            entropy_triggered = bool(detection_context.get("entropy_triggered"))
            threat_detected = bool(detection_context.get("threat_detected")) or bool(detected_processes)
            backup_access_alerts = list(detection_context.get("backup_access_alerts") or [])
            action_taken: list[str] = []
            timeline: list[dict[str, str]] = [
                {
                    "state": "SAFE",
                    "title": "System baseline state",
                    "timestamp": attack_start_time,
                }
            ]

            if detected_processes:
                self.emit_alert(
                    "Suspicious activity detected. Saving your work...",
                    extra={
                        "process_count": len(detected_processes),
                        "process_name": self._first_process_name(detected_processes),
                    },
                )
                timeline.append(
                    {
                        "state": "SUSPICIOUS_ACTIVITY",
                        "title": "Suspicious process behavior observed",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

            if threat_detected:
                timeline.append(
                    {
                        "state": "ATTACK_DETECTED",
                        "title": "Threat confidence crossed detection threshold",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

            for alert in backup_access_alerts:
                self._log_event(
                    "backup_folder_access",
                    action="critical_alert",
                    event_type="critical",
                    extra={
                        "path": str(alert.get("path") or ""),
                        "severity": "critical",
                    },
                )

            protected_paths = self._apply_write_protection(monitored_paths or [])
            if protected_paths:
                self._append_action(action_taken, "file_protection_enabled")
                self._log_event(
                    "file_protection_enabled",
                    action="restricted",
                    event_type="warning",
                    extra={"protected_paths": protected_paths[:40]},
                )

            backup_result: dict[str, object] = {}
            backup_thread = threading.Thread(
                target=lambda: backup_result.update(
                    self.backup_service.backup_active_files(lookback_seconds=lookback_seconds)
                ),
                name="cybershield-backup-intervention",
                daemon=True,
            )
            backup_thread.start()
            backup_thread.join()

            if int(backup_result.get("files_protected") or 0) > 0:
                self._append_action(action_taken, "backup_completed")
                self._log_event(
                    "backup_created",
                    action="backup_completed",
                    event_type="info",
                    extra={
                        "files_protected": int(backup_result.get("files_protected") or 0),
                        "backup_versions": int(backup_result.get("backup_versions") or 0),
                    },
                )

            for process in detected_processes:
                result = self.process_service.suspend_process(int(process.get("pid") or 0))
                if bool(result.get("success")) and str(result.get("action") or "") in {"suspended", "priority_reduced"}:
                    self._append_action(action_taken, "process_suspended")
                    timeline.append(
                        {
                            "state": "PROCESS_SUSPENDED",
                            "title": "Suspicious process temporarily suspended",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                    self._log_event(
                        "process_suspended",
                        action=str(result.get("action") or "suspended"),
                        event_type="critical",
                        extra={
                            "pid": int(process.get("pid") or 0),
                            "process": str(process.get("name") or ""),
                            "score": float(process.get("score") or 0.0),
                        },
                    )

            if recheck_delay_seconds > 0:
                time.sleep(float(recheck_delay_seconds))

            confirmed_processes = self._re_evaluate(
                monitored_paths,
                cpu_threshold,
                {int(process.get("pid") or 0) for process in detected_processes},
            )

            for process in confirmed_processes:
                score = float(process.get("score") or 0.0)
                if score < float(terminate_threshold):
                    continue

                result = self.process_service.neutralize_threat(process, terminate_threshold=terminate_threshold)
                if str(result.get("action") or "") == "terminated" and bool(result.get("success")):
                    self._append_action(action_taken, "process_terminated")
                    timeline.append(
                        {
                            "state": "PROCESS_TERMINATED",
                            "title": "Confirmed malicious process terminated",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                    self._log_event(
                        "process_terminated",
                        action="terminated",
                        event_type="critical",
                        extra={
                            "pid": int(process.get("pid") or 0),
                            "process": str(process.get("name") or ""),
                            "score": score,
                        },
                    )

            restore_result: dict[str, object] = {}
            restore_thread = threading.Thread(
                target=lambda: restore_result.update(
                    self.recovery_service.restore_affected_files(
                        lookback_seconds=lookback_seconds,
                        before_timestamp=time.time() - 0.25,
                    )
                ),
                name="cybershield-restore-intervention",
                daemon=True,
            )
            restore_thread.start()
            restore_thread.join()

            files_restored = int(restore_result.get("files_restored") or 0)
            if files_restored > 0:
                self._append_action(action_taken, "files_restored")
                timeline.append(
                    {
                        "state": "FILES_RESTORED",
                        "title": "Protected files restored from versioned backups",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
            self._log_event(
                "files_restored",
                action="restored" if files_restored > 0 else "attempted",
                event_type="info" if files_restored > 0 else "warning",
                extra={
                    "files_restored": files_restored,
                    "restored_files": list(restore_result.get("restored_files") or []),
                },
            )

            if threat_level == "HIGH":
                network_result = isolate_network(mode="aggressive")
                self._append_action(action_taken, "network_isolated")
                self._log_event(
                    "network_isolation_attempted",
                    action="isolated" if bool(network_result.get("isolated")) else "attempted",
                    event_type="critical",
                    extra=network_result,
                )

            timeline.append(
                {
                    "state": "SYSTEM_SAFE",
                    "title": "System returned to safe operating state",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )

            forensic_evidence: dict[str, object] = {
                "status": "SAFE",
                "threat_score": threat_score,
                "confidence": confidence,
                "actions": action_taken,
                "files_protected": int(backup_result.get("files_protected") or 0),
                "files_recovered": files_restored,
                "attack_start_time": attack_start_time,
                "file_activity_rate": float(detection_context.get("file_activity_rate") or 0.0),
                "suspicious_processes": detected_processes,
                "confirmed_processes": confirmed_processes,
                "process_tree": detection_context.get("process_tree") or [],
                "entropy": float(detection_context.get("entropy") or 0.0),
                "entropy_triggered": entropy_triggered,
                "dna_mismatch_count": int(detection_context.get("dna_mismatch_count") or 0),
                "affected_files": detection_context.get("affected_files") or [],
                "timeline": timeline,
            }
            evidence_package: dict[str, object] = {
                "pending": not bool(generate_forensics),
                "package_dir": "",
            }
            try:
                if generate_forensics:
                    evidence_package = self.forensic_service.generate_incident_package(evidence=forensic_evidence)
            finally:
                self._release_write_protection()

            self.system_state = "SAFE"
            response = {
                "status": "SAFE",
                "threat_detected": threat_detected,
                "confidence": confidence,
                "entropy_triggered": entropy_triggered,
                "action_taken": action_taken,
                "actions": action_taken,
                "files_protected": int(backup_result.get("files_protected") or 0),
                "files_recovered": files_restored,
                "threat_score": threat_score,
                "suspicious_processes": detected_processes,
                "confirmed_processes": confirmed_processes,
                "process_tree": detection_context.get("process_tree") or [],
                "entropy": float(detection_context.get("entropy") or 0.0),
                "backup_access_alerts": backup_access_alerts,
                "timeline": timeline,
                "evidence_package": evidence_package,
                "forensic_evidence": forensic_evidence,
                "forensic_pending": not bool(generate_forensics),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self._log_event(
                "system_safe",
                action="restored",
                event_type="info",
                extra={
                    "files_protected": response["files_protected"],
                    "files_recovered": response["files_recovered"],
                },
            )
            return response
