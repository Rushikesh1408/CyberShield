from __future__ import annotations

import os
import sys
import threading
import time
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from flask import Flask, jsonify, request, send_file

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from backend.config import AppConfig
    from backend.core import CyberShieldPipeline
    from backend.database import Database
    from backend.fingerprint import FingerprintManager
else:
    from .config import AppConfig
    from .core import CyberShieldPipeline
    from .database import Database
    from .fingerprint import FingerprintManager

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKUP_ROOT = PROJECT_ROOT / "backup"
DATA_ROOT = PROJECT_ROOT / "data"
DATABASE_PATH = DATA_ROOT / "cybershield.db"
ATTACK_REPORT_PATH = DATA_ROOT / "attack_report.txt"
FALLBACK_PROTECTED_FOLDER = PROJECT_ROOT / "protected_folder"
MONITOR_PATHS_ENV = "CYBERSHIELD_MONITOR_PATHS"
TRIGGER_THRESHOLD_ENV = "CYBERSHIELD_TRIGGER_THRESHOLD"
MAX_FILE_ACTIVITY_ENV = "CYBERSHIELD_MAX_FILE_ACTIVITY"
MAX_DNA_MISMATCH_ENV = "CYBERSHIELD_MAX_DNA_MISMATCH"
TWILIO_ACCOUNT_SID_ENV = "CYBERSHIELD_TWILIO_ACCOUNT_SID"
TWILIO_AUTH_TOKEN_ENV = "CYBERSHIELD_TWILIO_AUTH_TOKEN"
TWILIO_FROM_NUMBER_ENV = "CYBERSHIELD_TWILIO_FROM_NUMBER"
SMS_TIMEOUT_SECONDS = 8


def _existing_directories(candidates: list[Path]) -> list[Path]:
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if not resolved.exists() or not resolved.is_dir():
            continue
        key = str(resolved).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(resolved)
    return unique


def _normalize_contact_value(value: str) -> str:
    compact = "".join(ch for ch in str(value or "") if ch.isdigit() or ch == "+")
    if compact.startswith("+"):
        digits = "".join(ch for ch in compact[1:] if ch.isdigit())
        return f"+{digits}" if digits else ""
    return "".join(ch for ch in compact if ch.isdigit())


def _configured_monitor_directories() -> list[Path]:
    raw_value = str(os.environ.get(MONITOR_PATHS_ENV, "") or "").strip()
    if not raw_value:
        return []

    candidates: list[Path] = []
    for token in raw_value.replace(";", ",").split(","):
        cleaned = token.strip().strip('"').strip("'")
        if not cleaned:
            continue
        candidates.append(Path(cleaned))

    return _existing_directories(candidates)


def _read_int_env(name: str, default: int) -> int:
    raw_value = str(os.environ.get(name, "") or "").strip()
    if not raw_value:
        return int(default)

    try:
        return int(raw_value)
    except (TypeError, ValueError):
        return int(default)


def discover_protected_directories() -> list[Path]:
    configured = _configured_monitor_directories()
    if configured:
        return configured

    home = Path.home()
    candidates = [
        home / "Documents",
        home / "Downloads",
        home / "Desktop",
    ]
    protected = _existing_directories(candidates)
    if protected:
        return protected

    FALLBACK_PROTECTED_FOLDER.mkdir(parents=True, exist_ok=True)
    return [FALLBACK_PROTECTED_FOLDER.resolve()]


class SystemController:
    def __init__(self) -> None:
        self.database = Database(DATABASE_PATH)
        self.fingerprint_manager = FingerprintManager(self.database)
        self.protected_directories = discover_protected_directories()
        self.pipeline: CyberShieldPipeline | None = None
        self._pipeline_thread: threading.Thread | None = None
        self._pipeline_stop_event = threading.Event()
        self._attack_active = False
        self._warning_active = False
        self._last_recovery_count = 0
        self._emergency_alert_sent_for_attack = False
        self._emergency_alert_skip_logged_for_attack = False
        self._start_engine()

    def _start_engine(self) -> None:
        using_custom_monitor_paths = bool(str(os.environ.get(MONITOR_PATHS_ENV, "") or "").strip())
        default_trigger_threshold = 45 if using_custom_monitor_paths else 70
        default_max_file_activity = 10 if using_custom_monitor_paths else 200
        default_max_dna_mismatch = 3 if using_custom_monitor_paths else 20

        self.pipeline = CyberShieldPipeline(
            watch_paths=self.protected_directories,
            backup_root=BACKUP_ROOT,
            network_mode="safe",
            threat_score_trigger=max(1, _read_int_env(TRIGGER_THRESHOLD_ENV, default_trigger_threshold)),
            max_file_activity=max(1, _read_int_env(MAX_FILE_ACTIVITY_ENV, default_max_file_activity)),
            max_dna_mismatch=max(1, _read_int_env(MAX_DNA_MISMATCH_ENV, default_max_dna_mismatch)),
        )
        self.pipeline.start()
        self._pipeline_stop_event.clear()
        self._pipeline_thread = threading.Thread(
            target=self._pipeline_loop,
            name="cybershield-pipeline-loop",
            daemon=True,
        )
        self._pipeline_thread.start()
        self.database.log_event(
            {
                "event": "monitoring_started",
                "event_type": "info",
                "action": "none",
                "file_name": "",
                "file_path": "",
                "cpu_usage": 0.0,
                "file_rate": 0.0,
                "paths": [str(path) for path in self.protected_directories],
            }
        )

    def _pipeline_loop(self) -> None:
        while not self._pipeline_stop_event.wait(1.0):
            if self.pipeline is None:
                continue

            try:
                assessment = self.pipeline.run_cycle()
                self._record_pipeline_cycle(assessment)
            except (RuntimeError, ValueError, OSError) as error:
                self.database.insert_log(
                    "error",
                    "pipeline_cycle_failed",
                    metadata={"error": str(error)},
                )

    def _record_pipeline_cycle(self, assessment: dict[str, Any]) -> None:
        metrics = assessment.get("metrics") if isinstance(assessment.get("metrics"), dict) else {}
        assessment_timestamp = float(assessment.get("timestamp") or time.time())
        score = self._to_int(assessment.get("score"))
        level = str(assessment.get("level") or "LOW")
        triggered = bool(assessment.get("triggered"))
        trigger_threshold = max(1, self._to_int(assessment.get("trigger_threshold") or 70))
        warning_threshold = max(40, trigger_threshold - 20)

        files_per_second = float(metrics.get("file_activity_rate") or 0.0)
        activity_count = self._to_int(metrics.get("file_activity_count"))
        cpu_usage = float(metrics.get("cpu_usage") or 0.0)
        dna_mismatch_count = self._to_int(metrics.get("dna_mismatch_count"))

        status = "UNDER_ATTACK" if triggered else "SAFE"
        self.database.insert_metrics(
            files_per_second,
            activity_count,
            activity_count,
            cpu_usage,
            status,
        )

        if score >= warning_threshold:
            if not self._warning_active:
                self._warning_active = True
                self.database.insert_alert(
                    "UNDER_ATTACK",
                    "Early Threat Detection",
                    (
                        "Threshold-based early warning using behavioral anomalies "
                        "such as CPU spikes and high file access rate."
                    ),
                    severity="medium",
                )
                self.database.log_event(
                    {
                        "event": "early_threat_detection",
                        "event_type": "warning",
                        "action": "flagged",
                        "file_name": "",
                        "file_path": "",
                        "cpu_usage": cpu_usage,
                        "file_rate": files_per_second,
                        "score": score,
                        "level": level,
                        "dna_mismatch_count": dna_mismatch_count,
                    }
                )
        else:
            self._warning_active = False

        if triggered:
            if not self._attack_active:
                self._attack_active = True
                self._emergency_alert_sent_for_attack = False
                self._emergency_alert_skip_logged_for_attack = False
                self.database.insert_alert(
                    "UNDER_ATTACK",
                    "Behavioral attack pattern confirmed",
                    "Pipeline threat score crossed attack threshold.",
                    severity="critical",
                )
                self.database.log_event(
                    {
                        "event": "attack_detected",
                        "event_type": "critical",
                        "action": "flagged",
                        "file_name": "",
                        "file_path": "",
                        "cpu_usage": cpu_usage,
                        "file_rate": files_per_second,
                        "score": score,
                        "level": level,
                        "modifications": activity_count,
                        "accesses": activity_count,
                        "dna_mismatch_count": dna_mismatch_count,
                    }
                )

                self._record_attack_fingerprint(
                    files_per_second=files_per_second,
                    activity_count=activity_count,
                    cpu_usage=cpu_usage,
                )

                actions = assessment.get("actions") if isinstance(assessment.get("actions"), list) else []
                for action_entry in actions:
                    if not isinstance(action_entry, dict):
                        continue
                    if str(action_entry.get("type") or "") != "network_isolation":
                        continue

                    result = action_entry.get("result") if isinstance(action_entry.get("result"), dict) else {}
                    isolated = bool(result.get("isolated"))
                    mode = str(result.get("mode") or "safe")
                    simulated = bool(result.get("simulated"))
                    self.database.log_event(
                        {
                            "event": "active_threat_neutralization",
                            "event_type": "critical",
                            "action": "isolated" if isolated else "attempted",
                            "file_name": "",
                            "file_path": "",
                            "cpu_usage": cpu_usage,
                            "file_rate": files_per_second,
                            "mode": mode,
                            "isolated": isolated,
                            "simulated": simulated,
                        }
                    )
                    self.database.insert_alert(
                        "UNDER_ATTACK",
                        "Active Threat Neutralization",
                        (
                            f"Network isolation {'executed' if isolated else 'attempted'} "
                            f"in {mode} mode."
                        ),
                        severity="high",
                    )
                    break

                restored_files = self._run_automatic_restore(
                    assessment_timestamp=assessment_timestamp,
                    score=score,
                    level=level,
                    cpu_usage=cpu_usage,
                    file_rate=files_per_second,
                )
                self._last_recovery_count = len(restored_files)

                self._write_attack_report(
                    score=score,
                    level=level,
                    files_affected=activity_count,
                    files_recovered=self._last_recovery_count,
                    cpu_usage=cpu_usage,
                    file_rate=files_per_second,
                )
            elif not ATTACK_REPORT_PATH.exists():
                self._write_attack_report(
                    score=score,
                    level=level,
                    files_affected=activity_count,
                    files_recovered=self._last_recovery_count,
                    cpu_usage=cpu_usage,
                    file_rate=files_per_second,
                )

            self._send_emergency_alert_once(
                assessment_timestamp=assessment_timestamp,
                score=score,
                level=level,
                cpu_usage=cpu_usage,
                file_rate=files_per_second,
            )
            return

        if self._attack_active:
            self._attack_active = False
            self._last_recovery_count = 0
            self._emergency_alert_sent_for_attack = False
            self._emergency_alert_skip_logged_for_attack = False
            self.database.insert_alert(
                "SAFE",
                "System Safe",
                "Pipeline threat score returned to safe range.",
                severity="medium",
            )
            self.database.log_event(
                {
                    "event": "system_safe",
                    "event_type": "info",
                    "action": "restored",
                    "file_name": "",
                    "file_path": "",
                    "cpu_usage": cpu_usage,
                    "file_rate": files_per_second,
                    "score": score,
                    "level": level,
                }
            )

    def _dominant_activity_extension(self) -> str:
        if self.pipeline is None:
            return "unknown"

        try:
            recent_paths = self.pipeline.recent_activity_paths(lookback_seconds=120.0, limit=40)
        except (RuntimeError, ValueError, OSError):
            recent_paths = []

        if not recent_paths:
            return "unknown"

        counts: dict[str, int] = {}
        for file_path in recent_paths:
            suffix = Path(str(file_path)).suffix.lower().strip()
            extension = suffix if suffix else "unknown"
            counts[extension] = counts.get(extension, 0) + 1

        return max(counts.items(), key=lambda item: item[1])[0]

    def _record_attack_fingerprint(
        self,
        *,
        files_per_second: float,
        activity_count: int,
        cpu_usage: float,
    ) -> None:
        extension = self._dominant_activity_extension()
        modification_rate = max(float(files_per_second), float(activity_count))
        access_rate = float(activity_count)

        fingerprint = self.fingerprint_manager.create(
            process_name="cybershield-pipeline",
            file_extension=extension,
            modification_rate=modification_rate,
            access_rate=access_rate,
            cpu_spike=float(cpu_usage),
        )
        similar = self.fingerprint_manager.compare(fingerprint)
        self.fingerprint_manager.store(fingerprint)

        similarity = float(similar.get("similarity") or 0.0) if isinstance(similar, dict) else 0.0
        self.database.log_event(
            {
                "event": "attack_fingerprint_recorded",
                "event_type": "info",
                "action": "stored",
                "file_name": "",
                "file_path": "",
                "cpu_usage": float(cpu_usage),
                "file_rate": float(files_per_second),
                "signature_hash": str(fingerprint.get("signature_hash") or ""),
                "extension": extension,
                "similarity": similarity,
            }
        )

        if not isinstance(similar, dict):
            return

        self.database.insert_alert(
            "UNDER_ATTACK",
            "Known attack fingerprint matched",
            (
                "Current behavior matches a previously seen attack pattern "
                f"({similarity:.1f}% similarity)."
            ),
            severity="high",
            fingerprint_match=str(similar.get("signature_hash") or ""),
        )

    def _send_sms_via_twilio(self, *, phone: str, message: str) -> tuple[bool, str]:
        account_sid = str(os.environ.get(TWILIO_ACCOUNT_SID_ENV, "") or "").strip()
        auth_token = str(os.environ.get(TWILIO_AUTH_TOKEN_ENV, "") or "").strip()
        from_number = str(os.environ.get(TWILIO_FROM_NUMBER_ENV, "") or "").strip()

        if not account_sid or not auth_token or not from_number:
            return False, "twilio_not_configured"

        endpoint = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
        form = urllib.parse.urlencode({"To": phone, "From": from_number, "Body": message}).encode(
            "utf-8"
        )
        request_obj = urllib.request.Request(endpoint, data=form, method="POST")
        basic_token = base64.b64encode(f"{account_sid}:{auth_token}".encode("utf-8")).decode("ascii")
        request_obj.add_header("Authorization", f"Basic {basic_token}")
        request_obj.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            with urllib.request.urlopen(request_obj, timeout=SMS_TIMEOUT_SECONDS) as response:
                status_code = int(getattr(response, "status", 0) or 0)
                payload = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as error:
            payload = error.read().decode("utf-8", errors="replace")
            return False, f"twilio_http_{error.code}:{payload[:180]}"
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            return False, f"twilio_error:{error}"

        if 200 <= status_code < 300:
            return True, payload[:180]
        return False, f"twilio_http_{status_code}:{payload[:180]}"

    def _send_emergency_alert_once(
        self,
        *,
        assessment_timestamp: float,
        score: int,
        level: str,
        cpu_usage: float,
        file_rate: float,
    ) -> None:
        if self._emergency_alert_sent_for_attack:
            return

        emergency_phone = self.get_emergency_contact().strip()
        if not emergency_phone:
            if self._emergency_alert_skip_logged_for_attack:
                return

            self._emergency_alert_skip_logged_for_attack = True
            self.database.log_event(
                {
                    "event": "emergency_alert_skipped",
                    "event_type": "warning",
                    "action": "none",
                    "file_name": "",
                    "file_path": "",
                    "cpu_usage": cpu_usage,
                    "file_rate": file_rate,
                    "reason": "contact_not_configured",
                    "threat_confidence": score,
                    "threat_level": level,
                }
            )
            return

        alert_timestamp = datetime.fromtimestamp(float(assessment_timestamp), tz=timezone.utc).isoformat()
        alert_message = (
            "CyberShield Emergency Alert\n"
            f"Threat: {level} ({score}%)\n"
            "Ransomware attack behavior detected.\n"
            "Active Threat Neutralization + Automatic System Recovery triggered.\n"
            f"Time: {alert_timestamp}"
        )

        sent, provider_response = self._send_sms_via_twilio(
            phone=emergency_phone,
            message=alert_message,
        )

        # One outbound SMS attempt per attack cycle.
        self._emergency_alert_sent_for_attack = True

        if sent:
            self.database.insert_alert(
                "UNDER_ATTACK",
                "Emergency SOS Triggered",
                f"Emergency alert sent to {emergency_phone}.",
                severity="critical",
            )
            self.database.log_event(
                {
                    "event": "emergency_alert_sent",
                    "event_type": "critical",
                    "action": "none",
                    "file_name": "",
                    "file_path": "",
                    "cpu_usage": cpu_usage,
                    "file_rate": file_rate,
                    "phone": emergency_phone,
                    "provider": "twilio",
                }
            )
            return

        self.database.insert_alert(
            "UNDER_ATTACK",
            "Emergency SOS Failed",
            "Failed to deliver emergency SMS. Check Twilio environment configuration.",
            severity="high",
        )
        self.database.log_event(
            {
                "event": "emergency_alert_failed",
                "event_type": "warning",
                "action": "none",
                "file_name": "",
                "file_path": "",
                "cpu_usage": cpu_usage,
                "file_rate": file_rate,
                "phone": emergency_phone,
                "provider": "twilio",
                "error": provider_response,
            }
        )

    def _write_attack_report(
        self,
        *,
        score: int,
        level: str,
        files_affected: int,
        files_recovered: int,
        cpu_usage: float,
        file_rate: float,
    ) -> None:
        report_timestamp = datetime.now(timezone.utc).isoformat()
        report_body = (
            "--- CyberShield Attack Report ---\n\n"
            f"Time: {report_timestamp}\n"
            f"Threat Confidence: {score}%\n"
            f"Threat Level: {level}\n"
            f"CPU Usage: {round(cpu_usage, 2)}%\n"
            f"File Activity Rate: {round(file_rate, 2)} /s\n"
            f"Files Affected: {files_affected}\n"
            f"Files Recovered: {files_recovered}\n\n"
            "Actions Taken:\n"
            "Active Threat Neutralization attempted\n"
            "Automatic System Recovery ready\n\n"
            "Status:\n"
            "System secured and monitoring continues.\n"
        )

        try:
            ATTACK_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
            ATTACK_REPORT_PATH.write_text(report_body, encoding="utf-8")
        except OSError as error:
            self.database.insert_log(
                "warning",
                "attack_report_write_failed",
                metadata={"error": str(error)},
            )
            return

        self.database.log_event(
            {
                "event": "attack_report_generated",
                "event_type": "info",
                "action": "none",
                "file_name": ATTACK_REPORT_PATH.name,
                "file_path": str(ATTACK_REPORT_PATH),
                "cpu_usage": cpu_usage,
                "file_rate": file_rate,
                "files_affected": files_affected,
                "files_recovered": files_recovered,
                "threat_confidence": score,
                "threat_level": level,
                "timestamp": report_timestamp,
            }
        )

    def _run_automatic_restore(
        self,
        *,
        assessment_timestamp: float,
        score: int,
        level: str,
        cpu_usage: float,
        file_rate: float,
    ) -> list[str]:
        if self.pipeline is None:
            return []

        restore_before = max(0.0, float(assessment_timestamp) - 0.5)
        restored: list[str] = []
        try:
            restored = self.pipeline.automatic_restore(
                before_timestamp=restore_before,
                lookback_seconds=90.0,
                limit=200,
            )
        except (RuntimeError, ValueError, OSError):
            restored = []

        normalized_restored: list[str] = []
        seen: set[str] = set()
        for value in restored:
            candidate = str(value).strip()
            key = candidate.lower()
            if not candidate or key in seen:
                continue
            seen.add(key)
            normalized_restored.append(candidate)

        restored_count = len(normalized_restored)
        self.database.log_event(
            {
                "event": "files_restored",
                "event_type": "info" if restored_count > 0 else "warning",
                "action": "restored" if restored_count > 0 else "attempted",
                "file_name": "",
                "file_path": "",
                "cpu_usage": cpu_usage,
                "file_rate": file_rate,
                "score": score,
                "level": level,
                "restored_count": restored_count,
                "restored_files": normalized_restored[:40],
            }
        )

        self.database.insert_alert(
            "SAFE" if restored_count > 0 else "UNDER_ATTACK",
            "Automatic System Recovery",
            (
                f"Automatic System Recovery restored {restored_count} file(s)."
                if restored_count > 0
                else "Automatic System Recovery attempted but no recoverable snapshots were found."
            ),
            severity="high" if restored_count > 0 else "medium",
        )

        return normalized_restored

    def restart(self) -> dict[str, Any]:
        if self.pipeline is not None and self.pipeline.monitor.is_running:
            return self.snapshot()

        self.protected_directories = discover_protected_directories()
        self._pipeline_stop_event.set()
        if self._pipeline_thread is not None and self._pipeline_thread.is_alive():
            self._pipeline_thread.join(timeout=3)
        self._pipeline_thread = None
        self.pipeline = None
        self._attack_active = False
        self._warning_active = False
        self._last_recovery_count = 0

        self._start_engine()
        return self.snapshot()

    def stop(self) -> dict[str, Any]:
        if self.pipeline is not None and self.pipeline.monitor.is_running:
            self._pipeline_stop_event.set()
            if self._pipeline_thread is not None and self._pipeline_thread.is_alive():
                self._pipeline_thread.join(timeout=3)
            self._pipeline_thread = None
            self.pipeline.stop()
            self._attack_active = False
            self._warning_active = False
            self._last_recovery_count = 0

            latest_metric = self.database.fetch_latest_metric() or {}
            self.database.log_event(
                {
                    "event": "monitoring_stopped",
                    "event_type": "info",
                    "action": "none",
                    "file_name": "",
                    "file_path": "",
                    "cpu_usage": float(latest_metric.get("cpu_percent") or 0.0),
                    "file_rate": float(latest_metric.get("files_per_second") or 0.0),
                    "paths": [str(path) for path in self.protected_directories],
                }
            )
        return self.snapshot()

    def backup_status(self) -> dict[str, Any]:
        if self.pipeline is not None:
            status = self.pipeline.snapshot_manager.status()
            status["status"] = "Active"
            if not status.get("last_backup_time"):
                status["last_backup_time"] = self.database.fetch_latest_event_timestamp("backup_snapshot_created")
            return status

        return {
            "status": "Inactive",
            "files_secured": 0,
            "backup_versions": 0,
            "last_backup_time": None,
            "recent_files": [],
            "backup_root": str(BACKUP_ROOT),
        }

    def run_backup(self) -> dict[str, Any]:
        if self.pipeline is None:
            return {"message": "backup_unavailable", "created": 0, "backup_status": self.backup_status()}

        results = self.pipeline.snapshot_folder()
        latest_metric = self.database.fetch_latest_metric() or {}
        self.database.log_event(
            {
                "event": "backup_snapshot_created",
                "event_type": "info",
                "action": "none",
                "file_name": "",
                "file_path": "",
                "cpu_usage": float(latest_metric.get("cpu_percent") or 0.0),
                "file_rate": float(latest_metric.get("files_per_second") or 0.0),
                "created_files": len(results),
            }
        )
        return {
            "message": "backup_completed",
            "created": len(results),
            "backup_status": self.backup_status(),
        }

    def recover_file(self, file_path: str) -> Path | None:
        if self.pipeline is None:
            return None

        restored_payload = self.pipeline.restore_file(file_path)
        restored = Path(str(restored_payload["source_path"])) if restored_payload is not None else None
        latest_metric = self.database.fetch_latest_metric() or {}
        event_type = "info" if restored is not None else "warning"
        event_name = "file_restored" if restored is not None else "restore_failed"
        action = "restored" if restored is not None else "none"
        self.database.log_event(
            {
                "event": event_name,
                "event_type": event_type,
                "action": action,
                "file_name": Path(file_path).name,
                "file_path": file_path,
                "cpu_usage": float(latest_metric.get("cpu_percent") or 0.0),
                "file_rate": float(latest_metric.get("files_per_second") or 0.0),
            }
        )
        return restored

    def restore_many(self, paths: list[str]) -> list[str]:
        if self.pipeline is None:
            return []

        restored = self.pipeline.restore_many(paths)
        latest_metric = self.database.fetch_latest_metric() or {}
        self.database.log_event(
            {
                "event": "manual_restore_requested",
                "event_type": "info",
                "action": "restored",
                "file_name": "",
                "file_path": "",
                "cpu_usage": float(latest_metric.get("cpu_percent") or 0.0),
                "file_rate": float(latest_metric.get("files_per_second") or 0.0),
                "paths": paths,
                "restored": restored,
            }
        )
        return restored

    def set_emergency_contact(self, phone: str) -> str:
        normalized_phone = _normalize_contact_value(phone)
        digits_only = "".join(ch for ch in normalized_phone if ch.isdigit())
        if len(digits_only) < 8:
            raise ValueError("invalid_phone")

        self.database.set_setting("emergency_contact", normalized_phone)

        latest_metric = self.database.fetch_latest_metric() or {}
        self.database.log_event(
            {
                "event": "emergency_contact_saved",
                "event_type": "info",
                "action": "none",
                "file_name": "",
                "file_path": "",
                "cpu_usage": float(latest_metric.get("cpu_percent") or 0.0),
                "file_rate": float(latest_metric.get("files_per_second") or 0.0),
                "phone": normalized_phone,
            }
        )
        return normalized_phone

    def get_emergency_contact(self) -> str:
        return self.database.get_setting("emergency_contact", "")

    @staticmethod
    def get_attack_report_path() -> Path:
        return ATTACK_REPORT_PATH

    def snapshot(self) -> dict[str, Any]:
        if self.pipeline is None:
            payload: dict[str, Any] = {
                "status": "SAFE",
                "confidence": 0,
                "is_monitoring": False,
                "metrics": {
                    "files_per_second": 0.0,
                    "modifications": 0,
                    "accesses": 0,
                    "cpu_percent": 0.0,
                    "threat_confidence": 0,
                    "status": "SAFE",
                },
                "alerts": [],
                "logs": [],
                "fingerprints": [],
                "monitored_paths": [str(path) for path in self.protected_directories],
                "core_pipeline": None,
            }
        else:
            pipeline_state = self.pipeline.status()
            threat = pipeline_state.get("threat") if isinstance(pipeline_state.get("threat"), dict) else {}
            threat_metrics = threat.get("metrics") if isinstance(threat.get("metrics"), dict) else {}

            score = self._to_int(threat.get("score"))
            status = "UNDER_ATTACK" if bool(threat.get("triggered")) else "SAFE"
            files_per_second = float(threat_metrics.get("file_activity_rate") or 0.0)
            activity_count = self._to_int(threat_metrics.get("file_activity_count"))
            cpu_percent = float(threat_metrics.get("cpu_usage") or 0.0)

            payload = {
                "status": status,
                "confidence": score,
                "is_monitoring": bool(pipeline_state.get("is_running", False)),
                "metrics": {
                    "files_per_second": round(files_per_second, 2),
                    "modifications": activity_count,
                    "accesses": activity_count,
                    "cpu_percent": round(cpu_percent, 2),
                    "cpu_percent_raw": round(cpu_percent, 2),
                    "cpu_percent_sampled": round(cpu_percent, 2),
                    "threat_confidence": score,
                    "status": status,
                },
                "alerts": self.database.fetch_alerts(20),
                "logs": self.database.fetch_logs(100),
                "fingerprints": self.database.fetch_fingerprints(),
                "monitored_paths": [str(path) for path in self.protected_directories],
                "core_pipeline": pipeline_state,
            }

        payload["monitor_paths"] = [str(path) for path in self.protected_directories]
        payload["monitoring_message"] = "Monitoring: Protected System Directories (Auto-configured)"
        payload["backup_root"] = str(BACKUP_ROOT)
        payload["database_path"] = str(DATABASE_PATH)
        return payload

    @staticmethod
    def _to_int(value: Any) -> int:
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return 0

    def file_stats(self) -> dict[str, int]:
        backup_state = self.backup_status()
        files_protected = self._to_int(backup_state.get("files_secured"))
        files_recovered = 0

        for log in self.database.fetch_logs(500):
            event = str(log.get("event") or "")
            metadata = log.get("metadata") if isinstance(log.get("metadata"), dict) else {}
            if event in {"automatic_system_recovery", "files_restored"}:
                files_recovered += self._to_int(metadata.get("restored_count"))
            elif event == "file_restored":
                files_recovered += 1

        return {
            "files_protected": files_protected,
            "files_recovered": files_recovered,
        }

    def attack_summary(self) -> dict[str, int]:
        stats = self.file_stats()
        files_encrypted = 0
        files_recovered = stats["files_recovered"]
        threat_confidence = self._to_int(self.snapshot().get("confidence", 0))

        for log in self.database.fetch_logs(500):
            event = str(log.get("event") or "")
            metadata = log.get("metadata") if isinstance(log.get("metadata"), dict) else {}
            if event == "attack_report_generated":
                files_encrypted = self._to_int(metadata.get("files_affected"))
                files_recovered = self._to_int(metadata.get("files_recovered")) or files_recovered
                threat_confidence = self._to_int(metadata.get("threat_confidence")) or threat_confidence
                break
            if event == "attack_detected" and files_encrypted == 0:
                files_encrypted = self._to_int(metadata.get("modifications"))

        return {
            "files_protected": stats["files_protected"],
            "files_encrypted": files_encrypted,
            "files_recovered": files_recovered,
            "threat_confidence": threat_confidence,
        }

    def timeline(self) -> list[dict[str, str]]:
        event_to_state: dict[str, tuple[str, str, str]] = {
            "early_threat_detection": (
                "SUSPICIOUS_ACTIVITY",
                "Early Threat Detection triggered",
                "warning",
            ),
            "pre_attack_warning": (
                "SUSPICIOUS_ACTIVITY",
                "Early Threat Detection triggered",
                "warning",
            ),
            "attack_detected": (
                "ATTACK_DETECTED",
                "Behavioral attack pattern confirmed",
                "critical",
            ),
            "active_threat_neutralization": (
                "PROCESS_TERMINATED",
                "Active Threat Neutralization executed",
                "critical",
            ),
            "process_killed": (
                "PROCESS_TERMINATED",
                "Active Threat Neutralization executed",
                "critical",
            ),
            "automatic_system_recovery": (
                "FILES_RESTORED",
                "Automatic System Recovery restored files",
                "info",
            ),
            "files_restored": (
                "FILES_RESTORED",
                "Automatic System Recovery restored files",
                "info",
            ),
            "system_safe": (
                "SYSTEM_SAFE",
                "System returned to safe state",
                "safe",
            ),
            "recovery_completed": (
                "SYSTEM_SAFE",
                "System returned to safe state",
                "safe",
            ),
        }

        entries: list[dict[str, str]] = [
            {
                "state": "SAFE",
                "title": "System Safe",
                "description": "Monitoring engine is active and stable.",
                "severity": "safe",
                "timestamp": "",
            }
        ]

        for log in reversed(self.database.fetch_logs(500)):
            event = str(log.get("event") or "")
            if event not in event_to_state:
                continue

            state, description, severity = event_to_state[event]
            if entries and entries[-1]["state"] == state:
                continue

            entries.append(
                {
                    "state": state,
                    "title": state.replace("_", " ").title(),
                    "description": description,
                    "severity": severity,
                    "timestamp": str(log.get("timestamp") or ""),
                }
            )

        return entries


def _controller_from_app(flask_app: Flask) -> SystemController:
    controller = flask_app.extensions.get("cybershield_controller")
    if isinstance(controller, SystemController):
        return controller

    controller = SystemController()
    flask_app.extensions["cybershield_controller"] = controller
    return controller


def register_routes(flask_app: Flask) -> None:
    @flask_app.after_request
    def add_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    @flask_app.route("/api/health", methods=["GET"])
    def health() -> Any:
        snapshot = _controller_from_app(flask_app).snapshot()
        return jsonify(
            {
                "ok": True,
                "system": "CyberShield - Ransomware Defense System",
                "status": snapshot["status"],
            }
        )

    @flask_app.route("/api/status", methods=["GET"])
    def status() -> Any:
        data = _controller_from_app(flask_app).snapshot()
        return jsonify(
            {
                "status": data["status"],
                "confidence": int(data.get("confidence") or 0),
                "is_monitoring": data.get("is_monitoring", False),
                "monitor_paths": data["monitor_paths"],
                "monitoring_message": data["monitoring_message"],
                "backup_root": data["backup_root"],
                "metrics": data["metrics"],
                "core_pipeline": data.get("core_pipeline"),
            }
        )

    @flask_app.route("/api/attack/summary", methods=["GET"])
    def attack_summary() -> Any:
        return jsonify(_controller_from_app(flask_app).attack_summary())

    @flask_app.route("/api/file-stats", methods=["GET"])
    def file_stats() -> Any:
        return jsonify(_controller_from_app(flask_app).file_stats())

    @flask_app.route("/api/timeline", methods=["GET"])
    def timeline() -> Any:
        return jsonify({"timeline": _controller_from_app(flask_app).timeline()})

    @flask_app.route("/api/metrics", methods=["GET"])
    def metrics() -> Any:
        controller = _controller_from_app(flask_app)
        data = controller.snapshot()
        return jsonify(
            {
                "metrics": data["metrics"],
                "history": controller.database.fetch_metrics(120),
            }
        )

    @flask_app.route("/api/alerts", methods=["GET"])
    def alerts() -> Any:
        return jsonify({"alerts": _controller_from_app(flask_app).database.fetch_alerts(50)})

    @flask_app.route("/api/logs", methods=["GET"])
    def logs() -> Any:
        return jsonify({"logs": _controller_from_app(flask_app).database.fetch_logs(100)})

    @flask_app.route("/api/logs/clear", methods=["POST"])
    def clear_logs() -> Any:
        deleted = _controller_from_app(flask_app).database.clear_logs()
        return jsonify({"message": "logs_cleared", "deleted": deleted})

    @flask_app.route("/api/fingerprints", methods=["GET"])
    def fingerprints() -> Any:
        return jsonify({"fingerprints": _controller_from_app(flask_app).database.fetch_fingerprints()})

    @flask_app.route("/api/backup/status", methods=["GET"])
    def backup_status() -> Any:
        return jsonify(_controller_from_app(flask_app).backup_status())

    @flask_app.route("/api/backup/run", methods=["POST"])
    def run_backup() -> Any:
        return jsonify(_controller_from_app(flask_app).run_backup())

    @flask_app.route("/api/backup/recover", methods=["POST"])
    def backup_recover() -> Any:
        controller = _controller_from_app(flask_app)
        body = request.get_json(silent=True) or {}
        file_path = str(body.get("file_path") or "").strip()
        if not file_path:
            return jsonify({"message": "file_path_required"}), 400

        restored = controller.recover_file(file_path)
        if restored is None:
            return jsonify({"message": "backup_not_found", "file_path": file_path}), 404

        return jsonify(
            {
                "message": "restored",
                "file_path": file_path,
                "restored_path": str(restored),
                "backup_status": controller.backup_status(),
            }
        )

    @flask_app.route("/api/backup/restore", methods=["POST"])
    def backup_restore() -> Any:
        return backup_recover()

    @flask_app.route("/api/emergency/contact", methods=["GET"])
    def get_emergency_contact() -> Any:
        return jsonify({"contact": _controller_from_app(flask_app).get_emergency_contact()})

    @flask_app.route("/api/emergency/contact", methods=["POST"])
    def save_emergency_contact() -> Any:
        controller = _controller_from_app(flask_app)
        body = request.get_json(silent=True) or {}
        phone = str(body.get("phone") or body.get("contact") or "").strip()
        if not phone:
            return jsonify({"message": "phone_required"}), 400

        try:
            saved_phone = controller.set_emergency_contact(phone)
        except ValueError:
            return jsonify({"message": "invalid_phone"}), 400

        return jsonify({"message": "contact_saved", "contact": saved_phone})

    @flask_app.route("/api/settings/contact", methods=["GET"])
    def get_settings_contact() -> Any:
        return get_emergency_contact()

    @flask_app.route("/api/settings/contact", methods=["POST"])
    def save_settings_contact() -> Any:
        return save_emergency_contact()

    @flask_app.route("/api/report", methods=["GET"])
    def get_report() -> Any:
        report_path = _controller_from_app(flask_app).get_attack_report_path()
        if not report_path.exists():
            return jsonify({"message": "report_not_found"}), 404

        return send_file(
            report_path,
            as_attachment=False,
            mimetype="text/plain",
        )

    @flask_app.route("/api/report/download", methods=["GET"])
    def download_report() -> Any:
        report_path = _controller_from_app(flask_app).get_attack_report_path()
        if not report_path.exists():
            return jsonify({"message": "report_not_found"}), 404

        return send_file(
            report_path,
            as_attachment=True,
            download_name="attack_report.txt",
            mimetype="text/plain",
        )

    @flask_app.route("/api/start", methods=["POST"])
    def start_monitoring() -> Any:
        snapshot = _controller_from_app(flask_app).restart()
        return jsonify({"message": "monitoring_started", "snapshot": snapshot})

    @flask_app.route("/api/stop", methods=["POST"])
    def stop_monitoring() -> Any:
        snapshot = _controller_from_app(flask_app).stop()
        return jsonify({"message": "monitoring_stopped", "snapshot": snapshot})

    @flask_app.route("/api/restore", methods=["POST"])
    def restore_now() -> Any:
        controller = _controller_from_app(flask_app)
        body = request.get_json(silent=True) or {}
        paths = body.get("paths") or []
        if controller.pipeline is None:
            return jsonify({"message": "restore_unavailable", "restored": []}), 503

        restored = controller.restore_many(paths)
        return jsonify({"message": "restored", "restored": restored})

    @flask_app.route("/api/config", methods=["GET"])
    def get_runtime_config() -> Any:
        controller = _controller_from_app(flask_app)
        return jsonify(
            {
                "monitor_paths": [str(path) for path in controller.protected_directories],
                "monitoring_message": "Monitoring: Protected System Directories (Auto-configured)",
                "backup_root": str(BACKUP_ROOT),
                "database_path": str(DATABASE_PATH),
            }
        )

    @flask_app.route("/api/ping", methods=["GET"])
    def ping() -> Any:
        return jsonify({"message": "CyberShield is running"})


def create_app() -> Flask:
    app_instance = Flask(__name__)
    config_obj = AppConfig.from_env()
    app_instance.config.from_mapping(config_obj.flask_mapping())
    register_routes(app_instance)
    return app_instance
